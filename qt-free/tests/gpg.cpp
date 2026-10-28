// SPDX-License-Identifier: LGPL-2.0-only
#include "wallet.hpp"
#include <cassert>
int main(int argc, char** argv)
{
    assert(argc >= 3);
    dw::Wallet w(argv[2]);
    if (std::string(argv[1]) == "create") {
        assert(argc == 4);
        w.create_gpg(argv[3]);
        w.folders["Passwords"]["emoji 😀"] = { dw::PASSWORD, dw::password_value("příliš 日本語 🔒") };
        w.folders["Native"]["added"] = { dw::PASSWORD, dw::password_value("native → Qt ✓") };
        w.save();
    } else {
        w.open("");
        assert(w.is_gpg());
        assert(dw::password_text(w.folders.at("Qt").at("added")) == "Qt → native ✓");
        w.save();
    }
}
