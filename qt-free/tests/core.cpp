// SPDX-License-Identifier: LGPL-2.0-only
#include "wallet.hpp"
#include <cassert>
#include <fstream>
#include <gcrypt.h>
#include <sys/stat.h>
#include <unistd.h>
using namespace dw;
int main()
{
    char temp[] = "/tmp/dome-wallet-core-XXXXXX";
    assert(mkdtemp(temp));
    std::filesystem::path dir(temp);
    auto path = dir / "fixture.kwl";
    Folders expected;
    {
        Wallet w(path);
        w.create("disposable-password");
        w.folders["Passwords"]["Unicode 😀"] = { PASSWORD, password_value("příliš žluťoučký 日本語 🔒") };
        w.folders["Maps"]["form"] = { MAP, map_value({ { "uživatel", "test" }, { "password", "not-real" } }) };
        w.folders["Streams"]["bytes"] = { STREAM, Bytes { 0, 1, 0, 255 } };
        w.folders["Empty"] = {};
        w.folders[""][""] = { PASSWORD, password_value("") };
        assert(password_text(w.folders[""][""]) == "");
        expected = w.folders;
        w.save();
        struct stat st {};
        assert(stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
    }
    {
        Wallet w(path);
        bool failed = false;
        try {
            w.open("wrong");
        } catch (const Error&) {
            failed = true;
        }
        assert(failed);
        w.open("disposable-password");
        assert(w.folders == expected);
        assert(password_text(w.folders["Passwords"]["Unicode 😀"]) == "příliš žluťoučký 日本語 🔒");
        w.change_password("replacement");
    }
    {
        Wallet w(path);
        bool failed = false;
        try {
            w.open("disposable-password");
        } catch (const Error&) {
            failed = true;
        }
        assert(failed);
        w.open("replacement");
        assert(w.folders == expected);
    }
    {
        auto data = read_private(path);
        data.back() ^= 1;
        atomic_write(path, data);
        Wallet w(path);
        bool failed = false;
        try {
            w.open("replacement");
        } catch (const Error&) {
            failed = true;
        }
        assert(failed);
    }
    // PAM can create the salt before the wallet file exists. Both creation
    // paths must retain that salt and produce a password-readable wallet.
    for (bool pam : { false, true }) {
        auto name = pam ? "pam" : "orphan";
        auto salt_path = dir / (std::string(name) + ".salt");
        auto wallet_path = dir / (std::string(name) + ".kwl");
        Bytes salt(56, 42), key(56);
        atomic_write(salt_path, salt, false);
        assert(!gcry_kdf_derive(
            "login", 5, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt.data(), salt.size(), 50000, key.size(), key.data()));
        {
            Wallet w(wallet_path);
            if (pam)
                w.open_hashed(key);
            else
                w.create("login");
            w.folders["PAM"]["entry"] = { PASSWORD, password_value("retained") };
            w.save();
        }
        assert(read_private(salt_path) == salt);
        Wallet w(wallet_path);
        w.open("login");
        assert(password_text(w.folders.at("PAM").at("entry")) == "retained");
    }
    assert(decode_name(encode_name("wallet/日本語;😀")) == "wallet/日本語;😀");
    {
        Bytes invalid { 0, 0, 0, 9 };
        Reader r(invalid);
        bool failed = false;
        try {
            r.string();
        } catch (const Error&) {
            failed = true;
        }
        assert(failed);
    }
    std::filesystem::remove_all(dir);
}
