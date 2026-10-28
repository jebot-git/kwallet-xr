// SPDX-License-Identifier: LGPL-2.0-only
#include "wallet.hpp"
#include <cerrno>
#include <fcntl.h>
#include <glib.h>
#include <memory>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
namespace dw {
void Writer::u32(uint32_t n)
{
    for (int s : { 24, 16, 8, 0 })
        data.push_back((n >> s) & 255);
}
void Writer::raw(std::span<const unsigned char> v) { data.insert(data.end(), v.begin(), v.end()); }
void Writer::bytes(std::span<const unsigned char> v)
{
    if (v.size() > UINT32_MAX - 2)
        throw Error("Value too large");
    u32(v.size());
    raw(v);
}
void Writer::string(const std::string& s)
{
    GError* e = nullptr;
    glong n = 0;
    auto* p = g_utf8_to_utf16(s.data(), s.size(), nullptr, &n, &e);
    if (!p) {
        std::string m = e->message;
        g_error_free(e);
        throw Error(m);
    }
    if (n > 32 * 1024 * 1024) {
        g_free(p);
        throw Error("String too large");
    }
    u32(n * 2);
    for (glong i = 0; i < n; i++) {
        data.push_back(p[i] >> 8);
        data.push_back(p[i] & 255);
    }
    explicit_bzero(p, n * 2);
    g_free(p);
}
std::span<const unsigned char> Reader::raw(size_t n)
{
    if (n > data.size() - pos)
        throw Error("Truncated data stream");
    auto out = data.subspan(pos, n);
    pos += n;
    return out;
}
uint32_t Reader::u32()
{
    auto b = raw(4);
    uint32_t n = 0;
    for (auto v : b)
        n = (n << 8) | v;
    return n;
}
Bytes Reader::bytes()
{
    uint32_t n = u32();
    if (n == UINT32_MAX)
        return {};
    auto v = raw(n);
    return Bytes(v.begin(), v.end());
}
std::string Reader::string()
{
    auto n = u32();
    if (n == UINT32_MAX || n == 0)
        return {};
    if (n % 2)
        throw Error("Odd UTF-16 byte length");
    auto v = raw(n);
    std::vector<gunichar2> u(n / 2);
    for (size_t i = 0; i < u.size(); i++)
        u[i] = (v[i * 2] << 8) | v[i * 2 + 1];
    glong written = 0;
    GError* e = nullptr;
    auto* p = g_utf16_to_utf8(u.data(), u.size(), nullptr, &written, &e);
    explicit_bzero(u.data(), u.size() * 2);
    if (!p) {
        std::string m = e ? e->message : "Invalid UTF-16";
        if (e)
            g_error_free(e);
        throw Error(m);
    }
    std::string out(p, written);
    explicit_bzero(p, written);
    g_free(p);
    return out;
}
Bytes password_value(const std::string& s)
{
    Writer w;
    w.string(s);
    return std::move(w.data);
}
std::string password_text(const Entry& e)
{
    if (e.type != PASSWORD)
        throw Error("Not a password entry");
    Reader r(e.value);
    auto s = r.string();
    if (!r.end())
        throw Error("Trailing password data");
    return s;
}
Bytes map_value(const std::map<std::string, std::string>& map)
{
    Writer w;
    w.u32(map.size());
    for (auto& [k, v] : map) {
        w.string(k);
        w.string(v);
    }
    return std::move(w.data);
}
std::map<std::string, std::string> map_text(const Entry& e)
{
    if (e.type != MAP)
        throw Error("Not a map entry");
    Reader r(e.value);
    uint32_t n = r.u32();
    if (n > 65535)
        throw Error("Too many map entries");
    std::map<std::string, std::string> map;
    while (n--) {
        auto k = r.string();
        auto v = r.string();
        if (!map.emplace(k, v).second)
            throw Error("Duplicate map key");
    }
    if (!r.end())
        throw Error("Trailing map data");
    return map;
}
std::string encode_name(const std::string& s)
{
    const std::string allowed
        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789^&'@{}[],$=!-#()%.+_\r\n\t\f\v ";
    std::string out;
    const char* h = "0123456789ABCDEF";
    for (unsigned char c : s) {
        if (allowed.find(c) != std::string::npos)
            out += c;
        else {
            out += ';';
            out += h[c >> 4];
            out += h[c & 15];
        }
    }
    if (out.empty() || out == "." || out == "..")
        throw Error("Invalid wallet name");
    return out;
}
std::string decode_name(const std::string& s)
{
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == ';' && i + 2 < s.size() && g_ascii_isxdigit(s[i + 1]) && g_ascii_isxdigit(s[i + 2])) {
            out += char(g_ascii_xdigit_value(s[i + 1]) * 16 + g_ascii_xdigit_value(s[i + 2]));
            i += 2;
        } else
            out += s[i];
    }
    return out;
}
Bytes read_private(const std::filesystem::path& p, size_t limit)
{
    int fd = open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        throw Error("Cannot open private wallet input");
    struct stat st {};
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0077) || st.st_size < 0
        || uint64_t(st.st_size) > limit) {
        close(fd);
        throw Error("Unsafe or oversized wallet input");
    }
    Bytes out(st.st_size);
    size_t n = 0;
    while (n < out.size()) {
        auto got = read(fd, out.data() + n, out.size() - n);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            close(fd);
            throw Error("Cannot read wallet input");
        }
        n += got;
    }
    unsigned char extra;
    int got = read(fd, &extra, 1);
    close(fd);
    if (got != 0)
        throw Error("Wallet input changed during read");
    return out;
}
void atomic_write(const std::filesystem::path& p, std::span<const unsigned char> b, bool replace)
{
    auto parent = p.parent_path();
    if (parent.empty())
        throw Error("An explicit wallet directory is required");
    struct stat st {};
    if (lstat(parent.c_str(), &st) || !S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0022))
        throw Error("Unsafe wallet directory");
    std::string tmp = (parent / ".dome-wallet-XXXXXX").string();
    int fd = mkostemp(tmp.data(), O_CLOEXEC);
    if (fd < 0)
        throw Error("Cannot create private wallet output");
    bool published = false;
    try {
        if (fchmod(fd, 0600))
            throw Error("Cannot set private output mode");
        size_t n = 0;
        while (n < b.size()) {
            auto size = write(fd, b.data() + n, b.size() - n);
            if (size < 0 && errno == EINTR)
                continue;
            if (size <= 0)
                throw Error("Wallet write failed");
            n += size;
        }
        if (fsync(fd))
            throw Error("Wallet sync failed");
        if (replace) {
            if (lstat(p.c_str(), &st) == 0 && (!S_ISREG(st.st_mode) || st.st_uid != getuid()))
                throw Error("Unsafe existing wallet output");
            if (rename(tmp.c_str(), p.c_str()))
                throw Error("Wallet publish failed");
        } else {
            if (link(tmp.c_str(), p.c_str()))
                throw Error("Wallet output already exists or cannot be created");
            unlink(tmp.c_str());
        }
        published = true;
        close(fd);
        fd = -1;
        int dir = open(parent.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        if (dir < 0 || fsync(dir)) {
            if (dir >= 0)
                close(dir);
            throw Error("Wallet directory sync failed");
        }
        close(dir);
    } catch (...) {
        if (fd >= 0)
            close(fd);
        if (!published)
            unlink(tmp.c_str());
        throw;
    }
}
}
