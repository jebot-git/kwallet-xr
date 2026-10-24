// SPDX-License-Identifier: LGPL-2.0-or-later
#include "prompt.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <cstdio>
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QJsonObject result;
    if (argc > 1 && QByteArray(argv[1]) == "confirm") {
        result.insert(QStringLiteral("choice"), int(DomePrompt::confirm(QStringLiteral("Confirm fixture"), QStringLiteral("OK"), QStringLiteral("Other"))));
    } else {
        auto secret = DomePrompt::password(QStringLiteral("<qt>A&amp;B%<br>line\nGETPIN</qt>"), true);
        result.insert(QStringLiteral("accepted"), secret.accepted);
        result.insert(QStringLiteral("size"), int(secret.value.size()));
        result.insert(QStringLiteral("hash"), QString::fromLatin1(QCryptographicHash::hash(secret.value, QCryptographicHash::Sha256).toHex()));
    }
    std::puts(QJsonDocument(result).toJson(QJsonDocument::Compact).constData());
}
