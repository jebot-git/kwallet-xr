// SPDX-License-Identifier: LGPL-2.0-only
// Test-only oracle: never links into the Qt-free backend.
#include "kwalletbackend.h"
#include "kwalletentry.h"
#include <QCoreApplication>
#include <QDataStream>
#include <QDir>
#include <QIODevice>
#include <cassert>
int main(int argc, char** argv)
{
    QCoreApplication a(argc, argv);
    assert(argc == 3);
    QString root = QString::fromLocal8Bit(argv[2]);
    assert(root.startsWith(QStringLiteral("/tmp/")));
    assert(qEnvironmentVariable("XDG_DATA_HOME") == root);
    assert(QDir().mkpath(root + QStringLiteral("/kwalletd")));
    KWallet::Backend w(QStringLiteral("interop"));
    w.setCipherType(KWallet::BACKEND_CIPHER_BLOWFISH);
    assert(w.open(QByteArray("interop-only-password")) == 0);
    if (QByteArray(argv[1]) == "create") {
        w.createFolder(QStringLiteral("Passwords"));
        w.setFolder(QStringLiteral("Passwords"));
        KWallet::Entry e;
        e.setKey(QString::fromUtf8("emoji 😀"));
        e.setType(KWallet::Wallet::Password);
        e.setValue(QString::fromUtf8("příliš 日本語 🔒"));
        w.writeEntry(&e);
        w.createFolder(QStringLiteral("Maps"));
        w.setFolder(QStringLiteral("Maps"));
        QMap<QString, QString> map { { QStringLiteral("username"), QString::fromUtf8("uživatel") },
            { QStringLiteral("password"), QStringLiteral("test-only") } };
        QByteArray bytes;
        QDataStream ds(&bytes, QIODevice::WriteOnly);
        ds << map;
        e.setKey(QStringLiteral("form"));
        e.setType(KWallet::Wallet::Map);
        e.setValue(bytes);
        w.writeEntry(&e);
        w.createFolder(QStringLiteral("Streams"));
        w.setFolder(QStringLiteral("Streams"));
        e.setKey(QStringLiteral("binary"));
        e.setType(KWallet::Wallet::Stream);
        e.setValue(QByteArray("\0\1\0\xff", 4));
        w.writeEntry(&e);
        assert(w.close(true) == 0);
    } else {
        assert(w.hasFolder(QStringLiteral("Native")));
        w.setFolder(QStringLiteral("Native"));
        auto* e = w.readEntry(QStringLiteral("added"));
        assert(e && e->password() == QString::fromUtf8("native → Qt ✓"));
        w.setFolder(QStringLiteral("Passwords"));
        e = w.readEntry(QString::fromUtf8("emoji 😀"));
        assert(e && e->password() == QString::fromUtf8("příliš 日本語 🔒"));
        if (QByteArray(argv[1]) == "check-update") {
            w.createFolder(QStringLiteral("Qt"));
            w.setFolder(QStringLiteral("Qt"));
            KWallet::Entry e;
            e.setKey(QStringLiteral("added"));
            e.setType(KWallet::Wallet::Password);
            e.setValue(QString::fromUtf8("Qt → native ✓"));
            w.writeEntry(&e);
            assert(w.close(true) == 0);
        } else
            assert(w.close(false) == 0);
    }
}
