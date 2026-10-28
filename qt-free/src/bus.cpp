// SPDX-License-Identifier: LGPL-2.0-or-later
#include "bus.hpp"
#include "introspection.hpp"
#include "secrets.hpp"
#include <csignal>
#include <glib-unix.h>
namespace dw {
Variant child(GVariant* v, size_t n)
{
    if (!v || n >= g_variant_n_children(v))
        throw Error("Invalid method arguments");
    return Variant(g_variant_get_child_value(v, n));
}
std::string str(GVariant* v)
{
    if (!v || (!g_variant_is_of_type(v, G_VARIANT_TYPE_STRING) && !g_variant_is_of_type(v, G_VARIANT_TYPE_OBJECT_PATH)))
        throw Error("Expected a string argument");
    gsize size = 0;
    auto* s = g_variant_get_string(v, &size);
    if (size > 65536)
        throw Error("Argument is too large");
    return std::string(s, size);
}
std::string string_arg(GVariant* v, size_t n)
{
    auto c = child(v, n);
    return str(c.v);
}
int integer_arg(GVariant* v, size_t n)
{
    auto c = child(v, n);
    if (!g_variant_is_of_type(c.v, G_VARIANT_TYPE_INT32))
        throw Error("Expected integer argument");
    return g_variant_get_int32(c.v);
}
bool bool_arg(GVariant* v, size_t n)
{
    auto c = child(v, n);
    if (!g_variant_is_of_type(c.v, G_VARIANT_TYPE_BOOLEAN))
        throw Error("Expected boolean argument");
    return g_variant_get_boolean(c.v);
}
Bytes byte_array(GVariant* v)
{
    if (!g_variant_is_of_type(v, G_VARIANT_TYPE("ay")))
        throw Error("Expected a byte array");
    gsize n = 0;
    auto* p = static_cast<const unsigned char*>(g_variant_get_fixed_array(v, &n, 1));
    if (n > 8 * 1024 * 1024)
        throw Error("Secret data too large");
    return Bytes(p, p + n);
}
GVariant* bytes_variant(std::span<const unsigned char> v)
{
    return g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, v.data(), v.size(), 1);
}
GVariant* strings_variant(const std::vector<std::string>& v, bool objects)
{
    GVariantBuilder b;
    g_variant_builder_init(&b, G_VARIANT_TYPE(objects ? "ao" : "as"));
    for (auto& s : v)
        g_variant_builder_add(&b, objects ? "o" : "s", s.c_str());
    return g_variant_builder_end(&b);
}
Json string_map(GVariant* v)
{
    if (!g_variant_is_of_type(v, G_VARIANT_TYPE("a{ss}")))
        throw Error("Expected a string map");
    Json out = Json::object();
    GVariantIter iter;
    g_variant_iter_init(&iter, v);
    const char *k, *value;
    while (g_variant_iter_next(&iter, "{&s&s}", &k, &value)) {
        if (strlen(k) > 4096 || strlen(value) > 65536 || out.size() > 4096)
            throw Error("Attributes too large");
        out[k] = value;
    }
    return out;
}
GVariant* map_variant(const Json& map)
{
    GVariantBuilder b;
    g_variant_builder_init(&b, G_VARIANT_TYPE("a{ss}"));
    for (auto it = map.begin(); it != map.end(); ++it) {
        if (!it.value().is_string())
            continue;
        g_variant_builder_add(&b, "{ss}", it.key().c_str(), it.value().get_ref<const std::string&>().c_str());
    }
    return g_variant_builder_end(&b);
}
Call::Call(GDBusConnection* c, GDBusMessage* m)
    : connection(c)
    , message(m)
    , args(g_dbus_message_get_body(m))
{
    auto s = [](const char* p) { return std::string(p ? p : ""); };
    path = s(g_dbus_message_get_path(m));
    interface = s(g_dbus_message_get_interface(m));
    method = s(g_dbus_message_get_member(m));
    sender = s(g_dbus_message_get_sender(m));
    signature = s(g_dbus_message_get_signature(m));
    if (args && g_variant_get_size(args) > 12 * 1024 * 1024)
        throw Error("Method request too large");
}
void Call::reply(GVariant* body)
{
    auto* m = g_dbus_message_new_method_reply(message);
    g_dbus_message_set_body(m, body ? body : g_variant_new("()"));
    g_dbus_connection_send_message(connection, m, G_DBUS_SEND_MESSAGE_FLAGS_NONE, nullptr, nullptr);
    g_object_unref(m);
}
void Call::error(const char* name, const std::string& text)
{
    auto* m = g_dbus_message_new_method_error_literal(message, name, text.c_str());
    g_dbus_connection_send_message(connection, m, G_DBUS_SEND_MESSAGE_FLAGS_NONE, nullptr, nullptr);
    g_object_unref(m);
}
Service::Service(const std::filesystem::path& root)
    : backend(root)
{
    GError* e = nullptr;
    connection = g_bus_get_sync(G_BUS_TYPE_SESSION, nullptr, &e);
    if (!connection) {
        std::string text = e ? e->message : "No session bus";
        if (e)
            g_error_free(e);
        throw Error(text);
    }
    g_dbus_connection_set_exit_on_close(connection, false);
    backend.connection = connection;
    prompt_finished([this] { drain(); });
    loop = g_main_loop_new(nullptr, false);
    secrets = std::make_unique<Secrets>(*this);
    backend.changed = [this](auto& name, auto& event) { wallet_event(name, event); };
}
Service::~Service()
{
    prompt_finished({});
    for (auto* message : deferred)
        g_object_unref(message);
    if (filter)
        g_dbus_connection_remove_filter(connection, filter);
    secrets.reset();
    if (loop)
        g_main_loop_unref(loop);
    if (connection)
        g_object_unref(connection);
}
void Service::emit(
    const std::string& path, const char* iface, const char* signal, GVariant* body, const char* destination)
{
    g_dbus_connection_emit_signal(connection, destination, path.c_str(), iface, signal, body, nullptr);
}
void Service::run()
{
    if (!backend.enabled())
        throw Error("KWallet is disabled in configuration");
    g_timeout_add_seconds(
        15,
        [](gpointer p) -> gboolean {
            static_cast<Service*>(p)->backend.idle_close();
            return G_SOURCE_CONTINUE;
        },
        this);
    for (auto name : { "org.kde.kwalletd5", "org.kde.kwalletd6", "org.kde.ksecretd", "org.kde.secretservicecompat",
             "org.freedesktop.secrets", "org.freedesktop.impl.portal.desktop.kwallet" }) {
        Variant result(g_dbus_connection_call_sync(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus", "RequestName", g_variant_new("(su)", name, 4u), G_VARIANT_TYPE("(u)"),
            G_DBUS_CALL_FLAGS_NONE, 3000, nullptr, nullptr));
        guint value = 0;
        if (result.v)
            g_variant_get(result.v, "(u)", &value);
        if (value != 1)
            throw Error("A wallet or Secret Service provider already owns a required bus name");
    }
    filter = g_dbus_connection_add_filter(
        connection,
        [](GDBusConnection*, GDBusMessage* m, gboolean incoming, gpointer data) -> GDBusMessage* {
            auto* self = static_cast<Service*>(data);
            if (!incoming)
                return m;
            if (g_dbus_message_get_message_type(m) == G_DBUS_MESSAGE_TYPE_METHOD_CALL) {
                auto* dest = g_dbus_message_get_destination(m);
                auto* unique = g_dbus_connection_get_unique_name(self->connection);
                if (!dest
                    || (!g_str_has_prefix(dest, "org.kde.kwallet") && !g_str_has_prefix(dest, "org.kde.ksecret")
                        && strcmp(dest, "org.kde.secretservicecompat") && strcmp(dest, "org.freedesktop.secrets")
                        && strcmp(dest, "org.freedesktop.impl.portal.desktop.kwallet") && strcmp(dest, unique)))
                    return m;
                auto* job = new std::pair<Service*, GDBusMessage*>(self, G_DBUS_MESSAGE(g_object_ref(m)));
                g_main_context_invoke(
                    nullptr,
                    [](gpointer p) -> gboolean {
                        std::unique_ptr<std::pair<Service*, GDBusMessage*>> job(
                            static_cast<std::pair<Service*, GDBusMessage*>*>(p));
                        job->first->dispatch(job->second);
                        g_object_unref(job->second);
                        return G_SOURCE_REMOVE;
                    },
                    job);
                return nullptr;
            }
            return m;
        },
        this, nullptr);
    g_dbus_connection_signal_subscribe(
        connection, "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged", "/org/freedesktop/DBus",
        nullptr, G_DBUS_SIGNAL_FLAGS_NONE,
        [](GDBusConnection*, const gchar*, const gchar*, const gchar*, const gchar*, GVariant* p, gpointer data) {
            const char *name, *old, *now;
            g_variant_get(p, "(&s&s&s)", &name, &old, &now);
            auto* self = static_cast<Service*>(data);
            if (*old && !*now) {
                if (self->active_caller == old)
                    cancel_prompt();
                self->backend.disconnect(old);
                self->secrets->disconnect(old);
            }
        },
        this, nullptr);
    g_signal_connect(connection, "closed", G_CALLBACK(+[](GDBusConnection*, gboolean, GError*, gpointer data) {
        cancel_prompt();
        g_main_loop_quit(static_cast<Service*>(data)->loop);
    }),
        this);
    for (int signal : { SIGTERM, SIGINT, SIGHUP })
        g_unix_signal_add(
            signal,
            [](gpointer data) -> gboolean {
                cancel_prompt();
                g_main_loop_quit(static_cast<Service*>(data)->loop);
                return G_SOURCE_REMOVE;
            },
            this);
    g_main_loop_run(loop);
}
void Service::drain()
{
    auto messages = std::move(deferred);
    deferred.clear();
    for (auto* message : messages) {
        auto* job = new std::pair<Service*, GDBusMessage*>(this, message);
        g_idle_add(
            [](gpointer p) -> gboolean {
                std::unique_ptr<std::pair<Service*, GDBusMessage*>> job(
                    static_cast<std::pair<Service*, GDBusMessage*>*>(p));
                job->first->dispatch(job->second);
                g_object_unref(job->second);
                return G_SOURCE_REMOVE;
            },
            job);
    }
}
void Service::dispatch(GDBusMessage* m)
{
    try {
        Call call(connection, m);
        if (prompt_active()) {
            bool readonly = (call.interface == "org.freedesktop.DBus.Properties"
                                && (call.method == "Get" || call.method == "GetAll"))
                || call.interface == "org.freedesktop.DBus.Introspectable"
                || call.interface == "org.freedesktop.DBus.Peer"
                || (call.interface == "org.freedesktop.Secret.Prompt" && call.method == "Dismiss");
            if (!readonly) {
                if (deferred.size() >= 64)
                    call.error("org.freedesktop.DBus.Error.LimitsExceeded", "Credential request queue is full");
                else
                    deferred.push_back(G_DBUS_MESSAGE(g_object_ref(m)));
                return;
            }
        }
        struct CallerScope {
            Service& self;
            std::string previous;
            CallerScope(Service& s, const std::string& sender)
                : self(s)
                , previous(std::move(s.active_caller))
            {
                self.active_caller = sender;
            }
            ~CallerScope() { self.active_caller = std::move(previous); }
        } caller(*this, call.sender);
        if (call.interface == "org.freedesktop.DBus.Peer") {
            if (call.method == "Ping")
                call.reply(nullptr);
            else if (call.method == "GetMachineId") {
                call.reply(g_variant_new("(s)", g_dbus_connection_get_guid(connection)));
            } else
                call.error("org.freedesktop.DBus.Error.UnknownMethod", "Unknown peer method");
            return;
        }
        if (call.interface == "org.freedesktop.DBus.Introspectable" && call.method == "Introspect") {
            auto xml = introspection(call.path);
            call.reply(g_variant_new("(s)", xml.c_str()));
            return;
        }
        if (wallet_call(call) || secrets->call(call))
            return;
        call.error("org.freedesktop.DBus.Error.UnknownMethod", "Unknown wallet method");
    } catch (const std::exception& e) {
        auto* error = dynamic_cast<const Error*>(&e);
        auto* reply = g_dbus_message_new_method_error_literal(
            m, error ? error->bus_name.c_str() : "org.freedesktop.DBus.Error.Failed", e.what());
        g_dbus_connection_send_message(connection, reply, G_DBUS_SEND_MESSAGE_FLAGS_NONE, nullptr, nullptr);
        g_object_unref(reply);
    }
}
void Service::wallet_event(const std::string& name, const std::string& event)
{
    const char* signal = event == "created" ? "walletCreated"
        : event == "opened"                 ? "walletOpened"
        : event == "closed"                 ? "walletClosed"
        : event == "deleted"                ? "walletDeleted"
                                            : "folderListUpdated";
    emit("/modules/kwalletd6", "org.kde.KWallet", signal, g_variant_new("(s)", name.c_str()));
    if (event == "created" || event == "deleted")
        emit("/modules/kwalletd6", "org.kde.KWallet", "walletListDirty", g_variant_new("()"));
    if (secrets)
        secrets->changed(name, event);
}
}
