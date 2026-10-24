// SPDX-License-Identifier: LGPL-2.0-or-later
#include "prompt.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QProcess>
#include <QRegularExpression>
#include <QTimer>
#include <gpg-error.h>
#include <cstring>
#ifdef Q_OS_LINUX
#include <sys/prctl.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>
#endif

#ifndef DOME_PINENTRY_TIMEOUT_MS
#define DOME_PINENTRY_TIMEOUT_MS 180000
#endif

namespace DomePrompt {
void hardenProcess() {
#ifdef Q_OS_LINUX
    struct rlimit limit {0, 0};
    setrlimit(RLIMIT_CORE, &limit);
    prctl(PR_SET_DUMPABLE, 0);
#endif
}
void wipe(QByteArray &value) {
    if (!value.isEmpty()) explicit_bzero(value.data(), size_t(value.size()));
    value.clear();
}
static QString plain(QString text) {
    text.replace(QStringLiteral("<br />"), QStringLiteral("\n"));
    text.replace(QStringLiteral("<br>"), QStringLiteral("\n"));
    text.remove(QRegularExpression(QStringLiteral("<[^>]*>")));
    for (const auto &pair : {qMakePair("&lt;", "<"), qMakePair("&gt;", ">"), qMakePair("&quot;", "\""), qMakePair("&apos;", "'"), qMakePair("&amp;", "&")})
        text.replace(QString::fromLatin1(pair.first), QString::fromLatin1(pair.second));
    return text;
}
static QByteArray escape(const QString &text) {
    auto bytes = plain(text).toUtf8();
    bytes.replace("%", "%25"); bytes.replace("\r", "%0D"); bytes.replace("\n", "%0A");
    return bytes;
}
// A private child, fixed at build time: no shell, public bus password method,
// environment-based executable override, password argv, or secret temp files.
class Channel {
    QProcess process;
    QByteArray pending;
    QElapsedTimer deadline;
    bool valid = false;
    bool line(QByteArray &out) {
        while (!pending.contains('\n')) {
            auto bytes = process.readAllStandardOutput();
            pending.append(bytes); wipe(bytes);
            if (pending.size() > 16384) return false;
            if (pending.contains('\n')) break;
            if (process.state() == QProcess::NotRunning || deadline.elapsed() >= DOME_PINENTRY_TIMEOUT_MS) return false;
            QEventLoop loop;
            QTimer timer;
            timer.setSingleShot(true);
            QObject::connect(&process, &QProcess::readyReadStandardOutput, &loop, &QEventLoop::quit);
            QObject::connect(&process, &QProcess::finished, &loop, &QEventLoop::quit);
            QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
            timer.start(100);
            loop.exec();
        }
        const auto end = pending.indexOf('\n');
        out = pending.left(end);
        // Remove the consumed bytes without retaining an implicitly shared view.
        QByteArray rest(pending.constData() + end + 1, pending.size() - end - 1);
        wipe(pending); pending = std::move(rest);
        if (out.endsWith('\r')) out.chop(1);
        return true;
    }
    static bool decode(const QByteArray &line, QByteArray &value) {
        auto hex = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
        for (qsizetype i = 2; i < line.size(); ++i) {
            char c = line[i];
            if (c == '%') {
                if (i + 2 >= line.size()) return false;
                int high = hex(line[++i]); int low = hex(line[++i]);
                if (high < 0 || low < 0) return false;
                c = char((high << 4) | low);
            }
            if (c == 0 || value.size() >= 4096) return false;
            value.append(c);
        }
        return true;
    }
    Choice response(QByteArray *secret = nullptr) {
        QByteArray row;
        while (line(row)) {
            if (row == "OK" || row.startsWith("OK ")) { wipe(row); return Choice::Accept; }
            if (row.startsWith("ERR ")) {
                bool ok = false;
                const auto code = row.mid(4).split(' ').value(0).toUInt(&ok);
                wipe(row);
                return ok && (code & 0xffff) == GPG_ERR_NOT_CONFIRMED ? Choice::Other : Choice::Cancel;
            }
            if (row.startsWith("D ")) {
                if (!secret || !decode(row, *secret)) { wipe(row); return Choice::Cancel; }
            } else if (!(row.startsWith("S ") || row.startsWith('#') || row.isEmpty())) {
                wipe(row); return Choice::Cancel;
            }
            wipe(row);
        }
        wipe(row); return Choice::Cancel;
    }
public:
    Channel() {
        pending.reserve(16384);
        process.setStandardErrorFile(QProcess::nullDevice());
#ifdef Q_OS_LINUX
        // Do not leave a password window alive after its wallet daemon exits.
        process.setChildProcessModifier([parent = getpid()] {
            prctl(PR_SET_PDEATHSIG, SIGTERM);
            if (getppid() != parent) _exit(1);
        });
#endif
        process.start(QStringLiteral(DOME_PINENTRY_EXECUTABLE), {}, QIODevice::ReadWrite);
        deadline.start();
        valid = process.waitForStarted(3000) && response() == Choice::Accept;
        if (valid) valid = command("SETTIMEOUT 180") == Choice::Accept;
    }
    ~Channel() {
        if (process.state() != QProcess::NotRunning) {
            process.closeWriteChannel();
            if (!process.waitForFinished(100)) { process.kill(); process.waitForFinished(1000); }
        }
        wipe(pending);
        auto unread = process.readAllStandardOutput(); wipe(unread);
    }
    Choice command(const QByteArray &request, QByteArray *secret = nullptr) {
        if (!valid) return Choice::Cancel;
        const auto line = request + '\n';
        if (process.write(line) != line.size()) { valid = false; return Choice::Cancel; }
        const auto result = response(secret);
        if (result == Choice::Cancel && secret) wipe(*secret);
        return result;
    }
    bool setting(const QByteArray &name, const QString &value) { return command(name + ' ' + escape(value)) == Choice::Accept; }
};
Secret password(const QString &description, bool repeat, const QString &error) {
    Secret result;
    Channel channel;
    if (!channel.setting("SETTITLE", QStringLiteral("DomeD Wallet")) || !channel.setting("SETDESC", description)
        || !channel.setting("SETPROMPT", QStringLiteral("Wallet password:"))) return result;
    if (!error.isEmpty() && !channel.setting("SETERROR", error)) return result;
    if (repeat && !channel.setting("SETREPEAT", QStringLiteral("Repeat wallet password:"))) return result;
    result.accepted = channel.command("GETPIN", &result.value) == Choice::Accept;
    if (!result.accepted) wipe(result.value);
    return result;
}
Choice confirm(const QString &description, const QString &ok, const QString &other, const QString &title) {
    Channel channel;
    if (!channel.setting("SETTITLE", title.isEmpty() ? QStringLiteral("DomeD Wallet") : title)
        || !channel.setting("SETDESC", description) || !channel.setting("SETOK", ok)
        || !channel.setting("SETCANCEL", QStringLiteral("Cancel"))) return Choice::Cancel;
    if (!other.isEmpty() && !channel.setting("SETNOTOK", other)) return Choice::Cancel;
    return channel.command("CONFIRM");
}
void message(const QString &description, const QString &title) {
    Channel channel;
    if (channel.setting("SETTITLE", title.isEmpty() ? QStringLiteral("DomeD Wallet") : title) && channel.setting("SETDESC", description))
        channel.command("MESSAGE");
}
}
