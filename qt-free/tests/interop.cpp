// SPDX-License-Identifier: LGPL-2.0-only
#include "wallet.hpp"
#include <cassert>
int main(int argc, char** argv)
{
    assert(argc == 2);
    dw::Wallet w(argv[1]);
    w.open("interop-only-password");
    assert(w.folders.size() == 3);
    assert(dw::password_text(w.folders.at("Passwords").at("emoji 😀")) == "příliš 日本語 🔒");
    assert(dw::map_text(w.folders.at("Maps").at("form")).at("username") == "uživatel");
    assert(w.folders.at("Streams").at("binary").value == dw::Bytes({ 0, 1, 0, 255 }));
    w.folders["Native"]["added"] = { dw::PASSWORD, dw::password_value("native → Qt ✓") };
    w.save();
}
