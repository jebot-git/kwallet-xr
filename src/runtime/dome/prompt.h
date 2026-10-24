// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include <QByteArray>
#include <QString>
#include <KGuiItem>
namespace DomePrompt {
void wipe(QByteArray &value);
void hardenProcess();
struct Secret {
    bool accepted = false;
    QByteArray value;
    Secret() = default;
    Secret(const Secret &) = delete;
    Secret &operator=(const Secret &) = delete;
    Secret(Secret &&other) noexcept : accepted(other.accepted), value(std::move(other.value)) { other.accepted = false; }
    ~Secret() { wipe(value); }
};
enum class Choice { Accept, Other, Cancel };
Secret password(const QString &description, bool repeat = false, const QString &error = {});
Choice confirm(const QString &description, const QString &ok, const QString &other = {}, const QString &title = {});
void message(const QString &description, const QString &title = {});
namespace Messages {
enum { PrimaryAction = 1, SecondaryAction = 2 };
inline void error(void *, const QString &text, const QString &title = {}) { message(text, title); }
inline void errorWId(quintptr, const QString &text, const QString &title = {}) { message(text, title); }
inline void information(void *, const QString &text, const QString &title = {}) { message(text, title); }
inline int warningTwoActionsWId(quintptr, const QString &text, const QString &title, const KGuiItem &ok, const KGuiItem &) {
    return confirm(text, ok.text(), {}, title) == Choice::Accept ? PrimaryAction : SecondaryAction;
}
}
}
