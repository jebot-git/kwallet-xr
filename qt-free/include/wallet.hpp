// SPDX-License-Identifier: LGPL-2.0-only
// KWallet file serialization derives from KDE's kwalletbackend/persist handler.
#pragma once
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
namespace dw {
template <typename T> struct WipeAllocator : std::allocator<T> {
    using value_type = T;
    WipeAllocator() = default;
    template <typename U> WipeAllocator(const WipeAllocator<U>&) { }
    void deallocate(T* p, std::size_t n)
    {
        explicit_bzero(p, n * sizeof(T));
        std::allocator<T>::deallocate(p, n);
    }
    template <typename U> bool operator==(const WipeAllocator<U>&) const { return true; }
};
using Buffer = std::vector<unsigned char, WipeAllocator<unsigned char>>;
struct Bytes : Buffer {
    using Buffer::Buffer;
    Bytes() = default;
    Bytes(const Bytes&) = default;
    Bytes(Bytes&&) = default;
    Bytes& operator=(const Bytes&) = default;
    Bytes& operator=(Bytes&&) = default;
    ~Bytes()
    {
        if (!empty())
            explicit_bzero(data(), size());
    }
};
struct Error : std::runtime_error {
    std::string bus_name;
    explicit Error(const std::string& message, const std::string& name = "org.freedesktop.DBus.Error.Failed")
        : std::runtime_error(message)
        , bus_name(name)
    {
    }
};
struct Writer {
    Bytes data;
    void u32(uint32_t);
    void raw(std::span<const unsigned char>);
    void string(const std::string&);
    void bytes(std::span<const unsigned char>);
};
struct Reader {
    std::span<const unsigned char> data;
    size_t pos = 0;
    explicit Reader(std::span<const unsigned char> d)
        : data(d)
    {
    }
    uint32_t u32();
    std::span<const unsigned char> raw(size_t);
    Bytes bytes();
    std::string string();
    bool end() const { return pos == data.size(); }
};
struct Entry {
    int32_t type = 0;
    Bytes value;
    bool operator==(const Entry&) const = default;
};
using Entries = std::map<std::string, Entry>;
using Folders = std::map<std::string, Entries>;
constexpr int PASSWORD = 1, STREAM = 2, MAP = 3;
Bytes password_value(const std::string&);
std::string password_text(const Entry&);
Bytes map_value(const std::map<std::string, std::string>&);
std::map<std::string, std::string> map_text(const Entry&);
std::string encode_name(const std::string&);
std::string decode_name(const std::string&);
Bytes read_private(const std::filesystem::path&, size_t limit = 64 * 1024 * 1024);
void atomic_write(const std::filesystem::path&, std::span<const unsigned char>, bool replace = true);
struct Wallet {
    Folders folders;
    explicit Wallet(std::filesystem::path);
    ~Wallet();
    Wallet(const Wallet&) = delete;
    Wallet& operator=(const Wallet&) = delete;
    void create(std::string_view password);
    void open(std::string_view password);
    void open_hashed(std::span<const unsigned char> key);
    void create_gpg(const std::string& fingerprint);
    void save();
    void change_password(std::string_view password);
    bool is_gpg() const { return gpg_; }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_, salt_path_;
    Bytes key_;
    bool opened_ = false, gpg_ = false, legacy_ = false;
    std::string fingerprint_;
    int lock_ = -1;
    void lock_file();
    void decode(std::span<const unsigned char>);
    Bytes encode() const;
    void load_with_key(const Bytes&, Bytes);
};
}
