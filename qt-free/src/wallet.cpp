// SPDX-License-Identifier: LGPL-2.0-only
// File layout and legacy cipher use derived from KDE KWallet backend sources.
#include "wallet.hpp"
#include "blowfish.h"
#include "cbc.h"
#include "sha1.h"
#include <algorithm>
#include <array>
#include <fcntl.h>
#include <gcrypt.h>
#include <gpgme.h>
#include <memory>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
namespace dw {
namespace {
    constexpr unsigned char magic[] = { 'K', 'W', 'A', 'L', 'L', 'E', 'T', '\n', '\r', 0, '\r', '\n' };
    Bytes digest(int algo, std::span<const unsigned char> in)
    {
        Bytes out(gcry_md_get_algo_dlen(algo));
        if (algo == GCRY_MD_SHA1) {
            SHA1 sha;
            sha.process(in.data(), in.size());
            std::copy(sha.hash(), sha.hash() + 20, out.begin());
        } else
            gcry_md_hash_buffer(algo, out.data(), in.data(), in.size());
        return out;
    }
    Bytes derive(std::string_view password, std::span<const unsigned char> salt)
    {
        Bytes out(56);
        if (gcry_kdf_derive(password.data(), password.size(), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt.data(), salt.size(),
                50000, out.size(), out.data()))
            throw Error("Password derivation failed");
        return out;
    }
    Bytes old_hash(std::string_view password)
    {
        std::vector<Bytes> parts;
        for (size_t n = 0; n < std::max(size_t(1), std::min(size_t(4), (password.size() + 15) / 16)); n++) {
            auto chunk = password.substr(n * 16, n == 3 ? std::string::npos : 16);
            Bytes h(chunk.begin(), chunk.end());
            for (int i = 0; i < 2000; i++)
                h = digest(GCRY_MD_SHA1, h);
            parts.push_back(std::move(h));
        }
        Bytes out;
        for (size_t i = 0; i < parts.size(); i++) {
            size_t len = parts.size() == 4 ? 14 : parts.size() == 3 && i == 2 ? 16 : 20;
            out.insert(out.end(), parts[i].begin(), parts[i].begin() + len);
        }
        return out;
    }
    void randomize(Bytes& bytes) { gcry_randomize(bytes.data(), bytes.size(), GCRY_STRONG_RANDOM); }
    void skip_hashes(Reader& r)
    {
        auto n = r.u32();
        if (n > 65535)
            throw Error("Too many folders");
        while (n--) {
            r.raw(16);
            auto count = r.u32();
            if (count > 65535)
                throw Error("Too many entries");
            r.raw(size_t(count) * 16);
        }
    }
    Bytes hashes(const Folders& f)
    {
        Writer w;
        w.u32(f.size());
        for (auto& [folder, entries] : f) {
            w.raw(digest(GCRY_MD_MD5, std::span(reinterpret_cast<const unsigned char*>(folder.data()), folder.size())));
            w.u32(entries.size());
            for (auto& [name, e] : entries)
                w.raw(digest(GCRY_MD_MD5, std::span(reinterpret_cast<const unsigned char*>(name.data()), name.size())));
        }
        return std::move(w.data);
    }
    struct Gpg {
        gpgme_ctx_t ctx = nullptr;
        gpgme_data_t input = nullptr, output = nullptr;
        gpgme_key_t key = nullptr;
        Gpg()
        {
            gpgme_check_version(nullptr);
            if (gpgme_new(&ctx) || gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP))
                throw Error("Cannot initialize GPG");
        }
        ~Gpg()
        {
            if (key)
                gpgme_key_unref(key);
            if (input)
                gpgme_data_release(input);
            if (output)
                gpgme_data_release(output);
            if (ctx)
                gpgme_release(ctx);
        }
    };
    Bytes gpg(std::span<const unsigned char> in, std::string* keyid)
    {
        Gpg g;
        if (gpgme_data_new_from_mem(&g.input, reinterpret_cast<const char*>(in.data()), in.size(), 0)
            || gpgme_data_new(&g.output))
            throw Error("Cannot allocate GPG data");
        gpgme_error_t e;
        if (keyid) {
            if (gpgme_get_key(g.ctx, keyid->c_str(), &g.key, 0))
                throw Error("Cannot find wallet GPG key");
            *keyid = g.key->subkeys->keyid;
            gpgme_key_t keys[] = { g.key, nullptr };
            e = gpgme_op_encrypt(g.ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, g.input, g.output);
        } else
            e = gpgme_op_decrypt(g.ctx, g.input, g.output);
        if (e)
            throw Error("GPG wallet operation failed");
        if (gpgme_data_seek(g.output, 0, SEEK_SET) < 0)
            throw Error("Cannot seek GPG output");
        Bytes out;
        std::array<unsigned char, 4096> buf {};
        for (;;) {
            auto n = gpgme_data_read(g.output, buf.data(), buf.size());
            if (n < 0)
                throw Error("Cannot read GPG output");
            if (!n)
                break;
            if (out.size() + n > 64 * 1024 * 1024)
                throw Error("GPG output too large");
            out.insert(out.end(), buf.begin(), buf.begin() + n);
        }
        explicit_bzero(buf.data(), buf.size());
        return out;
    }
}
Wallet::Wallet(std::filesystem::path path)
    : path_(std::move(path))
    , salt_path_(path_)
{
    salt_path_.replace_extension(".salt");
    if (!gcry_check_version("1.5.0"))
        throw Error("libgcrypt unavailable");
}
Wallet::~Wallet()
{
    if (lock_ >= 0)
        close(lock_);
}
void Wallet::lock_file()
{
    if (lock_ >= 0)
        return;
    auto lock = path_;
    lock += ".dome-lock";
    lock_ = ::open(lock.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    struct stat st {};
    if (lock_ < 0 || fstat(lock_, &st) || !S_ISREG(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0077)
        || flock(lock_, LOCK_EX | LOCK_NB)) {
        if (lock_ >= 0)
            close(lock_);
        lock_ = -1;
        throw Error("Wallet is already in use or lock is unsafe");
    }
}
void Wallet::create(std::string_view password)
{
    lock_file();
    if (std::filesystem::exists(path_))
        throw Error("Wallet already exists");
    Bytes salt;
    if (std::filesystem::exists(salt_path_)) {
        salt = read_private(salt_path_, 56);
        if (salt.size() != 56)
            throw Error("Invalid wallet salt");
    } else {
        salt.resize(56);
        randomize(salt);
        atomic_write(salt_path_, salt, false);
    }
    key_ = derive(password, salt);
    opened_ = true;
    try {
        auto data = encode();
        atomic_write(path_, data, false);
    } catch (...) {
        opened_ = false;
        throw;
    }
}
void Wallet::open(std::string_view password)
{
    lock_file();
    auto data = read_private(path_);
    if (data.size() < 16 || !std::equal(std::begin(magic), std::end(magic), data.begin()))
        throw Error("Not a KWallet file");
    Bytes key;
    if (data[14] != 2) {
        if (data[13] == 1 || data[15] == 2) {
            auto salt = read_private(salt_path_, 56);
            if (salt.size() != 56)
                throw Error("Missing or invalid wallet salt");
            key = derive(password, salt);
        } else
            key = old_hash(password);
    }
    load_with_key(data, std::move(key));
}
void Wallet::open_hashed(std::span<const unsigned char> key)
{
    if (key.size() != 56)
        throw Error("Invalid PAM key size");
    lock_file();
    if (!std::filesystem::exists(path_)) {
        auto salt = read_private(salt_path_, 56);
        if (salt.size() != 56)
            throw Error("Invalid PAM wallet salt");
        key_ = Bytes(key.begin(), key.end());
        opened_ = true;
        legacy_ = false;
        gpg_ = false;
        try {
            auto encoded = encode();
            atomic_write(path_, encoded, false);
            return;
        } catch (...) {
            opened_ = false;
            throw;
        }
    }
    auto data = read_private(path_);
    if (data.size() < 16 || data[13] != 1 || data[14] != 3 || data[15] != 2)
        throw Error("Unsupported PAM wallet format");
    load_with_key(data, Bytes(key.begin(), key.end()));
}
void Wallet::load_with_key(const Bytes& data, Bytes key)
{
    if (data.size() < 16 || !std::equal(std::begin(magic), std::end(magic), data.begin()) || data[12] != 0
        || data[13] > 1)
        throw Error("Unsupported wallet version");
    Reader r(data);
    r.raw(16);
    Folders previous = std::move(folders);
    try {
        if (data[14] == 2 && data[15] == 0) {
            auto clear = gpg(r.raw(r.data.size() - r.pos), nullptr);
            Reader gp(clear);
            fingerprint_ = gp.string();
            auto hs = gp.bytes();
            Reader hr(hs);
            skip_hashes(hr);
            if (!hr.end())
                throw Error("Invalid GPG folder hashes");
            auto values = gp.bytes();
            if (!gp.end())
                throw Error("Trailing GPG wallet data");
            decode(values);
            gpg_ = true;
        } else {
            if ((data[14] != 0 && data[14] != 3) || (data[15] != 0 && data[15] != 2))
                throw Error("Unsupported wallet cipher");
            skip_hashes(r);
            auto encrypted = r.raw(r.data.size() - r.pos);
            if (encrypted.size() < 40 || encrypted.size() % 8)
                throw Error("Invalid wallet payload size");
            Bytes plain(encrypted.begin(), encrypted.end());
            BlowFish cipher;
            CipherBlockChain chain(&cipher, data[14] == 0);
            if (!chain.setKey(key.data(), key.size() * 8) || chain.decrypt(plain.data(), plain.size()) < 0)
                throw Error("Wallet decryption failed");
            Reader p(plain);
            p.raw(8);
            auto size = p.u32();
            if (size > plain.size() - 12 - 20)
                throw Error("Incorrect password or corrupt wallet");
            auto values = p.raw(size);
            auto check = digest(GCRY_MD_SHA1, values);
            unsigned diff = 0;
            for (size_t i = 0; i < 20; i++)
                diff |= check[i] ^ plain[plain.size() - 20 + i];
            if (diff)
                throw Error("Incorrect password or corrupt wallet");
            decode(values);
            gpg_ = false;
            legacy_ = data[13] == 0 && data[15] == 0;
        }
        key_ = std::move(key);
        opened_ = true;
    } catch (...) {
        folders = std::move(previous);
        throw;
    }
}
void Wallet::decode(std::span<const unsigned char> data)
{
    Reader r(data);
    Folders parsed;
    size_t total = 0;
    while (!r.end()) {
        auto folder = r.string();
        auto n = r.u32();
        if (n > 65535 || ++total > 65535 || parsed.contains(folder))
            throw Error("Invalid wallet folder structure");
        auto& entries = parsed[folder];
        while (n--) {
            auto name = r.string();
            auto type = r.u32();
            auto value = r.bytes();
            if (type < PASSWORD || type > MAP
                || !entries.emplace(name, Entry { int32_t(type), std::move(value) }).second)
                throw Error("Invalid wallet entry");
        }
    }
    folders = std::move(parsed);
}
Bytes Wallet::encode() const
{
    if (!opened_)
        throw Error("Wallet is locked");
    if (folders.size() > 65535)
        throw Error("Too many wallet folders");
    Writer values;
    for (auto& [folder, entries] : folders) {
        if (entries.size() > 65535)
            throw Error("Too many wallet entries");
        values.string(folder);
        values.u32(entries.size());
        for (auto& [name, e] : entries) {
            if (e.type < PASSWORD || e.type > MAP)
                throw Error("Invalid entry type");
            values.string(name);
            values.u32(e.type);
            values.bytes(e.value);
        }
    }
    auto index = hashes(folders);
    Writer output;
    output.raw(magic);
    if (gpg_) {
        output.raw(std::array<unsigned char, 4> { 0, 1, 2, 0 });
        Writer gp;
        auto keyid = fingerprint_;
        Gpg context;
        if (gpgme_get_key(context.ctx, keyid.c_str(), &context.key, 0))
            throw Error("GPG wallet key unavailable");
        keyid = context.key->subkeys->keyid;
        gp.string(keyid);
        gp.bytes(index);
        gp.bytes(values.data);
        output.raw(gpg(gp.data, &keyid));
    } else {
        if (key_.size() != 20 && key_.size() != 40 && key_.size() != 56)
            throw Error("Invalid wallet key size");
        output.raw(std::array<unsigned char, 4> {
            0, static_cast<unsigned char>(legacy_ ? 0 : 1), 3, static_cast<unsigned char>(legacy_ ? 0 : 2) });
        output.raw(index);
        size_t size = values.data.size() + 8 + 4 + 20;
        size_t padding = 8 - size % 8;
        Writer clear;
        Bytes random(8 + padding);
        randomize(random);
        clear.raw(std::span(random).first(8));
        clear.u32(values.data.size());
        clear.raw(values.data);
        clear.raw(std::span(random).subspan(8));
        clear.raw(digest(GCRY_MD_SHA1, values.data));
        BlowFish cipher;
        CipherBlockChain chain(&cipher);
        Bytes key = key_;
        if (!chain.setKey(key.data(), key.size() * 8) || chain.encrypt(clear.data.data(), clear.data.size()) < 0)
            throw Error("Wallet encryption failed");
        output.raw(clear.data);
    }
    if (output.data.size() > 64 * 1024 * 1024)
        throw Error("Wallet exceeds storage limit");
    return std::move(output.data);
}
void Wallet::save()
{
    auto data = encode();
    atomic_write(path_, data);
}
void Wallet::change_password(std::string_view password)
{
    if (!opened_ || gpg_)
        throw Error("Wallet is locked or uses GPG");
    Bytes salt;
    if (std::filesystem::exists(salt_path_))
        salt = read_private(salt_path_, 56);
    else {
        salt.resize(56);
        randomize(salt);
        atomic_write(salt_path_, salt, false);
    }
    if (salt.size() != 56)
        throw Error("Invalid salt");
    Bytes old = key_;
    bool old_legacy = legacy_;
    key_ = derive(password, salt);
    legacy_ = false;
    try {
        save();
    } catch (...) {
        key_ = std::move(old);
        legacy_ = old_legacy;
        throw;
    }
}
void Wallet::create_gpg(const std::string& fingerprint)
{
    lock_file();
    if (std::filesystem::exists(path_))
        throw Error("Wallet exists");
    fingerprint_ = fingerprint;
    gpg_ = true;
    opened_ = true;
    try {
        auto data = encode();
        atomic_write(path_, data, false);
    } catch (...) {
        opened_ = false;
        throw;
    }
}
}
