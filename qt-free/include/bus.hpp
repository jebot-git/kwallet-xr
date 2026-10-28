// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "backend.hpp"
namespace dw {
struct Variant {
    GVariant* v = nullptr;
    Variant() = default;
    explicit Variant(GVariant* p)
        : v(p)
    {
    }
    ~Variant()
    {
        if (v)
            g_variant_unref(v);
    }
    Variant(const Variant&) = delete;
    Variant(Variant&& o)
        : v(o.v)
    {
        o.v = nullptr;
    }
    Variant& operator=(Variant&& o)
    {
        if (v)
            g_variant_unref(v);
        v = o.v;
        o.v = nullptr;
        return *this;
    }
};
Variant child(GVariant*, size_t);
std::string str(GVariant*);
std::string string_arg(GVariant*, size_t);
int integer_arg(GVariant*, size_t);
bool bool_arg(GVariant*, size_t);
Bytes byte_array(GVariant*);
GVariant* bytes_variant(std::span<const unsigned char>);
GVariant* strings_variant(const std::vector<std::string>&, bool objects = false);
Json string_map(GVariant*);
GVariant* map_variant(const Json&);
struct Call {
    GDBusConnection* connection;
    GDBusMessage* message;
    GVariant* args;
    std::string path, interface, method, sender, signature;
    explicit Call(GDBusConnection*, GDBusMessage*);
    void reply(GVariant*);
    void error(const char*, const std::string&);
};
struct Secrets;
struct Service {
    GDBusConnection* connection = nullptr;
    GMainLoop* loop = nullptr;
    Backend backend;
    std::unique_ptr<Secrets> secrets;
    int next_transaction = 1;
    std::string active_caller;
    std::vector<GDBusMessage*> deferred;
    void drain();
    guint filter = 0;
    explicit Service(const std::filesystem::path&);
    ~Service();
    void run();
    void dispatch(GDBusMessage*);
    bool wallet_call(Call&);
    void emit(const std::string& path, const char* interface, const char* signal, GVariant*,
        const char* destination = nullptr);
    void wallet_event(const std::string&, const std::string&);
};
}
