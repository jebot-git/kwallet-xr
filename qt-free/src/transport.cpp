// SPDX-License-Identifier: LGPL-2.0-or-later
// Secret Service dh-ietf1024-sha256-aes128-cbc-pkcs7 transport.
#include "transport.hpp"
#include <algorithm>
#include <array>
#include <gcrypt.h>
namespace dw {
namespace {
    struct Mpi {
        gcry_mpi_t v = nullptr;
        ~Mpi() { gcry_mpi_release(v); }
    };
    struct Cipher {
        gcry_cipher_hd_t v = nullptr;
        ~Cipher() { gcry_cipher_close(v); }
    };
    Bytes hmac(std::span<const unsigned char> key, std::span<const unsigned char> data)
    {
        gcry_md_hd_t hd = nullptr;
        if (gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC) || gcry_md_setkey(hd, key.data(), key.size())) {
            if (hd)
                gcry_md_close(hd);
            throw Error("Cannot initialize session derivation");
        }
        gcry_md_write(hd, data.data(), data.size());
        auto* p = gcry_md_read(hd, GCRY_MD_SHA256);
        Bytes out(p, p + 32);
        gcry_md_close(hd);
        return out;
    }
}
std::pair<Bytes, Bytes> negotiate(std::span<const unsigned char> client)
{
    if (client.empty() || client.size() > 128)
        throw Error("Invalid DH public key length");
    const char* prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404"
                        "DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406"
                        "B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
    Mpi p, y, x, g, pub, shared, limit, q, check;
    gcry_mpi_scan(&p.v, GCRYMPI_FMT_HEX, prime, 0, nullptr);
    if (gcry_mpi_scan(&y.v, GCRYMPI_FMT_USG, client.data(), client.size(), nullptr))
        throw Error("Invalid DH public key");
    limit.v = gcry_mpi_copy(p.v);
    gcry_mpi_sub_ui(limit.v, limit.v, 2);
    if (gcry_mpi_cmp_ui(y.v, 2) < 0 || gcry_mpi_cmp(y.v, limit.v) > 0)
        throw Error("Invalid DH public key range");
    q.v = gcry_mpi_copy(p.v);
    gcry_mpi_sub_ui(q.v, q.v, 1);
    gcry_mpi_rshift(q.v, q.v, 1);
    check.v = gcry_mpi_new(1024);
    gcry_mpi_powm(check.v, y.v, q.v, p.v);
    if (gcry_mpi_cmp_ui(check.v, 1))
        throw Error("Invalid DH subgroup");
    Bytes random(32);
    gcry_randomize(random.data(), random.size(), GCRY_STRONG_RANDOM);
    gcry_mpi_scan(&x.v, GCRYMPI_FMT_USG, random.data(), random.size(), nullptr);
    g.v = gcry_mpi_set_ui(nullptr, 2);
    pub.v = gcry_mpi_new(1024);
    shared.v = gcry_mpi_new(1024);
    gcry_mpi_powm(pub.v, g.v, x.v, p.v);
    gcry_mpi_powm(shared.v, y.v, x.v, p.v);
    Bytes output(128), secret(128);
    size_t size = 0;
    if (gcry_mpi_print(GCRYMPI_FMT_USG, output.data(), output.size(), &size, pub.v))
        throw Error("DH output failed");
    if (size < 128) {
        std::move_backward(output.begin(), output.begin() + size, output.end());
        std::fill(output.begin(), output.begin() + 128 - size, 0);
    }
    if (gcry_mpi_print(GCRYMPI_FMT_USG, secret.data(), secret.size(), &size, shared.v))
        throw Error("DH shared key failed");
    if (size < 128) {
        std::move_backward(secret.begin(), secret.begin() + size, secret.end());
        std::fill(secret.begin(), secret.begin() + 128 - size, 0);
    }
    Bytes salt(32, 0);
    auto prk = hmac(salt, secret);
    std::array<unsigned char, 1> info { 1 };
    auto key = hmac(prk, info);
    key.resize(16);
    return { std::move(output), std::move(key) };
}
Bytes aes_encrypt(
    std::span<const unsigned char> key, std::span<const unsigned char> iv, std::span<const unsigned char> data)
{
    if (key.size() != 16 || iv.size() != 16 || data.size() > 8 * 1024 * 1024)
        throw Error("Invalid encryption parameters");
    Bytes out(data.begin(), data.end());
    unsigned char pad = 16 - out.size() % 16;
    out.insert(out.end(), pad, pad);
    Cipher c;
    if (gcry_cipher_open(&c.v, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0)
        || gcry_cipher_setkey(c.v, key.data(), key.size()) || gcry_cipher_setiv(c.v, iv.data(), iv.size())
        || gcry_cipher_encrypt(c.v, out.data(), out.size(), nullptr, 0))
        throw Error("Session encryption failed");
    return out;
}
Bytes aes_decrypt(
    std::span<const unsigned char> key, std::span<const unsigned char> iv, std::span<const unsigned char> data)
{
    if (key.size() != 16 || iv.size() != 16 || data.empty() || data.size() % 16 || data.size() > 8 * 1024 * 1024)
        throw Error("Invalid encrypted secret");
    Bytes out(data.begin(), data.end());
    Cipher c;
    if (gcry_cipher_open(&c.v, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0)
        || gcry_cipher_setkey(c.v, key.data(), key.size()) || gcry_cipher_setiv(c.v, iv.data(), iv.size())
        || gcry_cipher_decrypt(c.v, out.data(), out.size(), nullptr, 0))
        throw Error("Session decryption failed");
    size_t pad = out.back();
    unsigned invalid = pad == 0 || pad > 16;
    for (size_t i = 0; i < 16; i++)
        if (i < pad)
            invalid |= out[out.size() - 1 - i] ^ pad;
    if (invalid)
        throw Error("Invalid encrypted secret");
    out.resize(out.size() - pad);
    return out;
}
}
