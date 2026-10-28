// SPDX-License-Identifier: LGPL-2.0-or-later
#include "secrets.hpp"
#include "introspection.hpp"
#include "transport.hpp"
#include <ctime>
#include <gcrypt.h>
#include <gio/gunixfdlist.h>
#include <poll.h>
#include <unistd.h>
namespace dw {
namespace {
    constexpr const char* root = "/org/freedesktop/secrets";
    constexpr const char* collection = "org.freedesktop.Secret.Collection";
    constexpr const char* item = "org.freedesktop.Secret.Item";
    constexpr const char* service_iface = "org.freedesktop.Secret.Service";
    std::string hex(const std::string& s)
    {
        const char* h = "0123456789abcdef";
        std::string out = "c";
        for (unsigned char c : s) {
            out += h[c >> 4];
            out += h[c & 15];
        }
        return out;
    }
    Json props_map(GVariant* v)
    {
        if (!g_variant_is_of_type(v, G_VARIANT_TYPE("a{sv}")))
            throw Error("Invalid item properties");
        Json props = Json::object();
        GVariantIter it;
        g_variant_iter_init(&it, v);
        const char* k;
        GVariant* value;
        while (g_variant_iter_next(&it, "{&sv}", &k, &value)) {
            Variant val(value);
            if (g_variant_is_of_type(val.v, G_VARIANT_TYPE_STRING))
                props[k] = str(val.v);
            else if (g_variant_is_of_type(val.v, G_VARIANT_TYPE("a{ss}")))
                props[k] = string_map(val.v);
            else
                throw Error("Unsupported item property type");
        }
        return props;
    }
    std::vector<std::string> objects(GVariant* v)
    {
        if (!g_variant_is_of_type(v, G_VARIANT_TYPE("ao")))
            throw Error("Expected object paths");
        std::vector<std::string> out;
        GVariantIter it;
        g_variant_iter_init(&it, v);
        const char* p;
        while (g_variant_iter_next(&it, "&o", &p)) {
            if (out.size() > 4096)
                throw Error("Too many objects");
            out.push_back(p);
        }
        return out;
    }
    std::string token()
    {
        unsigned char b[16];
        gcry_randomize(b, sizeof(b), GCRY_STRONG_RANDOM);
        return hex(std::string(reinterpret_cast<char*>(b), sizeof(b)));
    }
    uint64_t stamp(const Json& metadata, const std::string& key)
    {
        try {
            if (metadata.contains(key) && metadata[key].is_string())
                return std::stoull(metadata[key].get<std::string>());
        } catch (...) {
        }
        return 0;
    }
}
std::string Secrets::collection_path(const std::string& wallet)
{
    return std::string(root) + "/collection/" + hex(wallet);
}
std::vector<std::string> Secrets::collections()
{
    std::vector<std::string> out;
    for (auto& name : service.backend.names())
        out.push_back(collection_path(name));
    return out;
}
std::string Secrets::wallet_name(const std::string& path)
{
    for (auto& name : service.backend.names())
        if (collection_path(name) == path)
            return name;
    throw Error("Unknown collection", "org.freedesktop.Secret.Error.NoSuchObject");
}
std::string Secrets::item_path(const ItemRef& r)
{
    return collection_path(r.wallet) + "/item/" + hex(r.folder + "/" + r.key);
}
std::vector<std::string> Secrets::items(const std::string& wallet)
{
    auto& s = service.backend.state(wallet);
    std::set<std::string> paths;
    if (s.wallet) {
        for (auto& [folder, entries] : s.wallet->folders)
            for (auto& [key, e] : entries)
                paths.insert(item_path({ wallet, folder, key }));
    }
    for (auto it = s.metadata.begin(); it != s.metadata.end(); ++it) {
        auto slash = it.key().find('/');
        if (it.value().is_object() && slash != std::string::npos)
            paths.insert(item_path({ wallet, it.key().substr(0, slash), it.key().substr(slash + 1) }));
    }
    return { paths.begin(), paths.end() };
}
ItemRef Secrets::item_ref(const std::string& path)
{
    for (auto& wallet : service.backend.names()) {
        auto& s = service.backend.state(wallet);
        if (s.wallet) {
            for (auto& [folder, entries] : s.wallet->folders)
                for (auto& [key, e] : entries) {
                    ItemRef r { wallet, folder, key };
                    if (item_path(r) == path)
                        return r;
                }
        }
        for (auto it = s.metadata.begin(); it != s.metadata.end(); ++it) {
            auto slash = it.key().find('/');
            if (it.value().is_object() && slash != std::string::npos) {
                ItemRef r { wallet, it.key().substr(0, slash), it.key().substr(slash + 1) };
                if (item_path(r) == path)
                    return r;
            }
        }
    }
    throw Error("Unknown secret item", "org.freedesktop.Secret.Error.NoSuchObject");
}
Json Secrets::attributes(const ItemRef& r)
{
    auto& s = service.backend.state(r.wallet);
    auto it = s.metadata.find(r.folder + "/" + r.key);
    if (it != s.metadata.end() && it->is_object())
        return it->value("attributes", Json::object());
    return Json::object();
}
std::string Secrets::mime(const ItemRef& r)
{
    auto& s = service.backend.state(r.wallet);
    auto it = s.metadata.find(r.folder + "/" + r.key);
    if (it != s.metadata.end() && it->is_object())
        return it->value("$fdo_mime_type", std::string("application/octet-stream"));
    return "application/octet-stream";
}
std::vector<std::string> Secrets::search(const Json& attrs, const std::string& only)
{
    std::vector<std::string> out;
    for (auto& w : service.backend.names()) {
        if (!only.empty() && w != only)
            continue;
        for (auto& p : items(w)) {
            auto ref = item_ref(p);
            auto a = attributes(ref);
            bool matches = true;
            for (auto it = attrs.begin(); it != attrs.end(); ++it)
                if (!a.contains(it.key()) || a[it.key()] != it.value())
                    matches = false;
            if (matches)
                out.push_back(p);
        }
    }
    return out;
}
std::string Secrets::prompt(const std::string& owner, std::function<GVariant*()> action)
{
    if (prompts.size() > 64)
        throw Error("Too many pending prompts");
    auto path = std::string(root) + "/prompt/p" + std::to_string(next_id++);
    prompts.emplace(path, Prompt { owner, std::move(action) });
    return path;
}
void Secrets::disconnect(const std::string& owner)
{
    for (auto it = sessions.begin(); it != sessions.end();)
        if (it->second.owner == owner)
            it = sessions.erase(it);
        else
            ++it;
    for (auto it = prompts.begin(); it != prompts.end();)
        if (it->second.owner == owner) {
            if (it->second.running)
                cancel_prompt();
            it = prompts.erase(it);
        } else
            ++it;
}
void Secrets::changed(const std::string& name, const std::string& event)
{
    const char* signal = event == "$fdo_created" ? "CollectionCreated"
        : event == "deleted"                     ? "CollectionDeleted"
                                                 : "CollectionChanged";
    service.emit(root, service_iface, signal, g_variant_new("(o)", collection_path(name).c_str()));
    if (event != "deleted") {
        GVariantBuilder b;
        g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
        g_variant_builder_add(&b, "{sv}", "Locked", g_variant_new_boolean(!service.backend.state(name).wallet));
        service.emit(collection_path(name), "org.freedesktop.DBus.Properties", "PropertiesChanged",
            g_variant_new("(s@a{sv}@as)", collection, g_variant_builder_end(&b), strings_variant({})));
    }
}
GVariant* Secrets::properties(const std::string& path, const std::string& iface)
{
    GVariantBuilder b;
    g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
    auto add = [&](const char* k, GVariant* v) { g_variant_builder_add(&b, "{sv}", k, v); };
    if (path == root && iface == service_iface)
        add("Collections", strings_variant(collections(), true));
    else if (path == "/org/freedesktop/portal/desktop" && iface == "org.freedesktop.impl.portal.Secret")
        add("version", g_variant_new_uint32(1));
    else if (iface == collection) {
        auto name = wallet_name(path);
        auto& s = service.backend.state(name);
        add("Items", strings_variant(items(name), true));
        add("Label", g_variant_new_string(s.metadata.value("$dome_label", name).c_str()));
        add("Locked", g_variant_new_boolean(!s.wallet));
        add("Created", g_variant_new_uint64(stamp(s.metadata, "$fdo_created")));
        add("Modified", g_variant_new_uint64(stamp(s.metadata, "$fdo_modified")));
    } else if (iface == item) {
        auto r = item_ref(path);
        auto& s = service.backend.state(r.wallet);
        Json meta = s.metadata.value(r.folder + "/" + r.key, Json::object());
        add("Locked", g_variant_new_boolean(!s.wallet));
        add("Attributes", map_variant(attributes(r)));
        add("Label", g_variant_new_string(meta.value("label", r.key).c_str()));
        add("Type",
            g_variant_new_string(
                attributes(r).value("xdg:schema", std::string("org.freedesktop.Secret.Generic")).c_str()));
        add("Created", g_variant_new_uint64(stamp(meta, "$fdo_created")));
        add("Modified", g_variant_new_uint64(stamp(meta, "$fdo_modified")));
    } else
        throw Error("Unknown properties interface");
    return g_variant_builder_end(&b);
}
Bytes Secrets::decrypt(GVariant* v, const std::string& owner)
{
    if (!g_variant_is_of_type(v, G_VARIANT_TYPE("(oayays)")))
        throw Error("Malformed secret structure");
    auto sid = string_arg(v, 0);
    auto it = sessions.find(sid);
    if (it == sessions.end() || it->second.owner != owner)
        throw Error("Invalid secret session or caller", "org.freedesktop.Secret.Error.NoSession");
    auto ivarg = child(v, 1), dataarg = child(v, 2);
    auto iv = byte_array(ivarg.v), data = byte_array(dataarg.v);
    if (it->second.key.empty()) {
        if (!iv.empty())
            throw Error("Unexpected plain session parameters");
        return data;
    }
    return aes_decrypt(it->second.key, iv, data);
}
GVariant* Secrets::secret(const ItemRef& r, const std::string& sid, const std::string& owner)
{
    auto it = sessions.find(sid);
    if (it == sessions.end() || it->second.owner != owner)
        throw Error("Invalid secret session or caller", "org.freedesktop.Secret.Error.NoSession");
    if (!service.backend.state(r.wallet).wallet)
        throw Error("Collection is locked", "org.freedesktop.Secret.Error.IsLocked");
    auto& s = service.backend.unlock(r.wallet, owner, "Secret Service application");
    auto& e = s.wallet->folders.at(r.folder).at(r.key);
    Bytes data = e.value;
    if (e.type == PASSWORD) {
        auto text = password_text(e);
        data = Bytes(text.begin(), text.end());
        explicit_bzero(text.data(), text.size());
    }
    Bytes iv;
    if (!it->second.key.empty()) {
        iv.resize(16);
        gcry_randomize(iv.data(), iv.size(), GCRY_STRONG_RANDOM);
        data = aes_encrypt(it->second.key, iv, data);
    }
    return g_variant_new("(o@ay@ays)", sid.c_str(), bytes_variant(iv), bytes_variant(data), mime(r).c_str());
}
bool Secrets::call(Call& c)
{
    if (c.interface.starts_with("org.freedesktop.Secret.") || c.interface == "org.freedesktop.DBus.Properties"
        || c.interface == "org.freedesktop.impl.portal.Secret") {
        if (!secret_signature(c.interface, c.method, c.signature)) {
            c.error("org.freedesktop.DBus.Error.InvalidArgs", "Invalid Secret Service method signature");
            return true;
        }
    }

    auto& m = c.method;
    auto& backend = service.backend;
    if (c.interface == "org.freedesktop.Secret.Session") {
        auto it = sessions.find(c.path);
        if (it == sessions.end() || it->second.owner != c.sender || m != "Close")
            throw Error("Invalid secret session or caller", "org.freedesktop.Secret.Error.NoSession");
        sessions.erase(it);
        c.reply(nullptr);
        return true;
    }
    if (c.interface == "org.freedesktop.Secret.Prompt") {
        auto it = prompts.find(c.path);
        if (it == prompts.end() || it->second.owner != c.sender)
            throw Error("Invalid prompt or caller");
        if (m == "Dismiss") {
            if (it->second.running) {
                cancel_prompt();
                c.reply(nullptr);
                return true;
            }
            prompts.erase(it);
            c.reply(nullptr);
            service.emit(c.path, "org.freedesktop.Secret.Prompt", "Completed",
                g_variant_new("(bv)", true, strings_variant({}, true)), c.sender.c_str());
            return true;
        }
        if (m != "Prompt")
            return false;
        if (it->second.running)
            throw Error("Prompt is already active");
        auto action = std::move(it->second.action);
        it->second.running = true;
        c.reply(nullptr);
        struct Job {
            Secrets* self;
            std::string path, owner;
            std::function<GVariant*()> action;
        };
        g_idle_add(
            [](gpointer p) -> gboolean {
                std::unique_ptr<Job> j(static_cast<Job*>(p));
                try {
                    auto* v = j->action();
                    j->self->service.emit(j->path, "org.freedesktop.Secret.Prompt", "Completed",
                        g_variant_new("(bv)", false, v), j->owner.c_str());
                } catch (...) {
                    j->self->service.emit(j->path, "org.freedesktop.Secret.Prompt", "Completed",
                        g_variant_new("(bv)", true, strings_variant({}, true)), j->owner.c_str());
                }
                j->self->prompts.erase(j->path);
                return G_SOURCE_REMOVE;
            },
            new Job { this, c.path, c.sender, std::move(action) });
        return true;
    }
    if (c.interface == "org.freedesktop.DBus.Properties") {
        auto iface = string_arg(c.args, 0);
        if (m == "GetAll") {
            c.reply(g_variant_new("(@a{sv})", properties(c.path, iface)));
            return true;
        }
        if (m == "Get") {
            Variant props(g_variant_ref_sink(properties(c.path, iface)));
            auto name = string_arg(c.args, 1);
            Variant v(g_variant_lookup_value(props.v, name.c_str(), nullptr));
            if (!v.v)
                throw Error("Unknown property");
            c.reply(g_variant_new("(v)", v.v));
            return true;
        }
        if (m == "Set") {
            auto name = string_arg(c.args, 1);
            auto wrapped = child(c.args, 2);
            Variant value(g_variant_get_variant(wrapped.v));
            if (iface == collection && name == "Label") {
                auto wallet = wallet_name(c.path);
                auto& s = backend.unlock(wallet, c.sender, "Secret Service application");
                s.metadata["$dome_label"] = str(value.v);
                backend.save_metadata(s);
            } else if (iface == item) {
                auto r = item_ref(c.path);
                if (!backend.state(r.wallet).wallet)
                    throw Error("Collection is locked", "org.freedesktop.Secret.Error.IsLocked");
                auto& s = backend.unlock(r.wallet, c.sender, "Secret Service application");
                auto& meta = s.metadata[r.folder + "/" + r.key];
                if (name == "Attributes")
                    meta["attributes"] = string_map(value.v);
                else if (name == "Label")
                    meta["label"] = str(value.v);
                else if (name == "Type")
                    meta["attributes"]["xdg:schema"] = str(value.v);
                else
                    throw Error("Read-only property");
                meta["$fdo_modified"] = std::to_string(time(nullptr));
                backend.save_metadata(s);
                service.emit(
                    collection_path(r.wallet), collection, "ItemChanged", g_variant_new("(o)", c.path.c_str()));
            } else
                throw Error("Read-only property");
            c.reply(nullptr);
            return true;
        }
        return false;
    }
    if (c.interface == service_iface && c.path == root) {
        if (m == "OpenSession") {
            auto algorithm = string_arg(c.args, 0);
            auto input = child(c.args, 1);
            Variant value(g_variant_get_variant(input.v));
            Bytes output, key;
            if (algorithm == "plain") {
                if (!g_variant_is_of_type(value.v, G_VARIANT_TYPE_STRING))
                    throw Error("Invalid plain negotiation");
            } else if (algorithm == "dh-ietf1024-sha256-aes128-cbc-pkcs7") {
                auto client = byte_array(value.v);
                auto result = negotiate(client);
                output = std::move(result.first);
                key = std::move(result.second);
            } else {
                c.error("org.freedesktop.DBus.Error.NotSupported", "Unsupported secret session algorithm");
                return true;
            }
            if (sessions.size() > 256)
                throw Error("Too many secret sessions");
            auto path = std::string(root) + "/session/s" + std::to_string(next_id++);
            sessions.emplace(path, Session { c.sender, std::move(key) });
            c.reply(g_variant_new(
                "(vo)", algorithm == "plain" ? g_variant_new_string("") : bytes_variant(output), path.c_str()));
            return true;
        }
        if (m == "CreateCollection") {
            auto p = child(c.args, 0);
            auto props = props_map(p.v);
            auto label = props.value(std::string(collection) + ".Label", std::string("Default"));
            auto alias = string_arg(c.args, 1);
            auto owner = c.sender;
            auto action = [this, label, alias, owner]() -> GVariant* {
                auto& s = service.backend.unlock(label, owner, "Secret Service application");
                s.metadata["$fdo_created"] = std::to_string(time(nullptr));
                s.metadata["$fdo_modified"] = s.metadata["$fdo_created"];
                s.metadata["$dome_label"] = label;
                service.backend.save_metadata(s);
                if (!alias.empty()) {
                    Json a = Json::object();
                    auto p = service.backend.root / ".dome-aliases.json";
                    if (std::filesystem::exists(p)) {
                        auto b = read_private(p);
                        a = Json::parse(b.begin(), b.end());
                    }
                    a[alias] = label;
                    auto t = a.dump();
                    atomic_write(p, std::span(reinterpret_cast<const unsigned char*>(t.data()), t.size()));
                }
                return g_variant_new_object_path(collection_path(label).c_str());
            };
            auto path = prompt(c.sender, std::move(action));
            c.reply(g_variant_new("(oo)", "/", path.c_str()));
            return true;
        }
        if (m == "ReadAlias") {
            auto alias = string_arg(c.args, 0);
            std::string name = alias == "default" ? backend.default_wallet() : "";
            auto p = backend.root / ".dome-aliases.json";
            if (std::filesystem::exists(p)) {
                auto b = read_private(p);
                auto a = Json::parse(b.begin(), b.end());
                name = a.value(alias, name);
            }
            auto names = backend.names();
            c.reply(g_variant_new("(o)",
                std::find(names.begin(), names.end(), name) != names.end() ? collection_path(name).c_str() : "/"));
            return true;
        }
        if (m == "SetAlias") {
            auto alias = string_arg(c.args, 0), path = string_arg(c.args, 1);
            auto p = backend.root / ".dome-aliases.json";
            Json a = Json::object();
            if (std::filesystem::exists(p)) {
                auto b = read_private(p);
                a = Json::parse(b.begin(), b.end());
            }
            if (path == "/")
                a.erase(alias);
            else {
                auto name = wallet_name(path);
                backend.unlock(name, c.sender, "Secret Service application");
                a[alias] = name;
            }
            auto t = a.dump();
            atomic_write(p, std::span(reinterpret_cast<const unsigned char*>(t.data()), t.size()));
            c.reply(nullptr);
            return true;
        }
        if (m == "SearchItems") {
            auto p = child(c.args, 0);
            auto matches = search(string_map(p.v));
            std::vector<std::string> unlocked, locked;
            for (auto& path : matches) {
                auto r = item_ref(path);
                (backend.state(r.wallet).wallet ? unlocked : locked).push_back(path);
            }
            c.reply(g_variant_new("(@ao@ao)", strings_variant(unlocked, true), strings_variant(locked, true)));
            return true;
        }
        if (m == "Unlock" || m == "Lock") {
            auto p = child(c.args, 0);
            auto paths = objects(p.v);
            std::vector<std::string> done, pending;
            for (auto& path : paths) {
                std::string wallet;
                try {
                    wallet = wallet_name(path);
                } catch (const Error&) {
                    wallet = item_ref(path).wallet;
                }
                auto& s = backend.state(wallet);
                if (m == "Lock") {
                    backend.lock(wallet);
                    done.push_back(path);
                } else if (s.wallet && s.owners.contains(c.sender))
                    done.push_back(path);
                else
                    pending.push_back(path);
            }
            std::string request = "/";
            if (!pending.empty()) {
                auto owner = c.sender;
                request = prompt(owner, [this, pending, owner]() -> GVariant* {
                    std::set<std::string> opened;
                    for (auto& path : pending) {
                        std::string wallet;
                        try {
                            wallet = wallet_name(path);
                        } catch (const Error&) {
                            wallet = item_ref(path).wallet;
                        }
                        if (opened.insert(wallet).second)
                            service.backend.unlock(wallet, owner, "Secret Service application");
                    }
                    return strings_variant(pending, true);
                });
            }
            c.reply(g_variant_new("(@aoo)", strings_variant(done, true), request.c_str()));
            return true;
        }
        if (m == "GetSecrets") {
            auto p = child(c.args, 0);
            auto paths = objects(p.v);
            auto session = string_arg(c.args, 1);
            GVariantBuilder b;
            g_variant_builder_init(&b, G_VARIANT_TYPE("a{o(oayays)}"));
            for (auto& path : paths)
                g_variant_builder_add(&b, "{o@(oayays)}", path.c_str(), secret(item_ref(path), session, c.sender));
            c.reply(g_variant_new("(@a{o(oayays)})", g_variant_builder_end(&b)));
            return true;
        }
        return false;
    }
    if (c.interface == collection) {
        auto name = wallet_name(c.path);
        if (m == "SearchItems") {
            auto p = child(c.args, 0);
            c.reply(g_variant_new("(@ao)", strings_variant(search(string_map(p.v), name), true)));
            return true;
        }
        if (m == "Delete") {
            auto owner = c.sender;
            auto path = prompt(owner, [this, name]() -> GVariant* {
                service.backend.erase(name);
                return strings_variant({}, true);
            });
            c.reply(g_variant_new("(o)", path.c_str()));
            return true;
        }
        if (m == "CreateItem") {
            if (!backend.state(name).wallet)
                throw Error("Collection is locked", "org.freedesktop.Secret.Error.IsLocked");
            auto& s = backend.unlock(name, c.sender, "Secret Service application");
            auto prop = child(c.args, 0), sv = child(c.args, 1);
            auto props = props_map(prop.v);
            auto data = decrypt(sv.v, c.sender);
            auto attrs = props.value(std::string(item) + ".Attributes", Json::object());
            auto label = props.value(std::string(item) + ".Label", std::string("Secret"));
            ItemRef r { name, "Secret Service", token() };
            bool replaced = false;
            if (bool_arg(c.args, 2)) {
                auto matches = search(attrs, name);
                if (!matches.empty()) {
                    r = item_ref(matches.front());
                    replaced = true;
                }
            }
            s.wallet->folders[r.folder][r.key] = { STREAM, std::move(data) };
            backend.save(s);
            s.metadata[r.folder + "/" + r.key] = Json { { "label", label }, { "attributes", attrs },
                { "$fdo_mime_type", string_arg(sv.v, 3) }, { "$fdo_created", std::to_string(time(nullptr)) },
                { "$fdo_modified", std::to_string(time(nullptr)) } };
            backend.save_metadata(s);
            auto path = item_path(r);
            service.emit(
                c.path, collection, replaced ? "ItemChanged" : "ItemCreated", g_variant_new("(o)", path.c_str()));
            c.reply(g_variant_new("(oo)", path.c_str(), "/"));
            return true;
        }
        return false;
    }
    if (c.interface == item) {
        auto r = item_ref(c.path);
        if (m == "GetSecret") {
            c.reply(g_variant_new("(@(oayays))", secret(r, string_arg(c.args, 0), c.sender)));
            return true;
        }
        if (m == "SetSecret") {
            if (!backend.state(r.wallet).wallet)
                throw Error("Collection is locked", "org.freedesktop.Secret.Error.IsLocked");
            auto& s = backend.unlock(r.wallet, c.sender, "Secret Service application");
            auto v = child(c.args, 0);
            auto data = decrypt(v.v, c.sender);
            auto& entry = s.wallet->folders.at(r.folder).at(r.key);
            auto content_type = string_arg(v.v, 3);
            if (entry.type == PASSWORD || content_type.starts_with("text/")
                || attributes(r).value("xdg:schema", std::string()) == "org.kde.KWallet.Password") {
                if (!g_utf8_validate(reinterpret_cast<const char*>(data.data()), data.size(), nullptr))
                    throw Error("Password secret must be valid UTF-8");
                std::string text(data.begin(), data.end());
                entry = { PASSWORD, password_value(text) };
                explicit_bzero(text.data(), text.size());
            } else
                entry = { STREAM, std::move(data) };
            backend.save(s);
            s.metadata[r.folder + "/" + r.key]["$fdo_mime_type"] = string_arg(v.v, 3);
            s.metadata[r.folder + "/" + r.key]["$fdo_modified"] = std::to_string(time(nullptr));
            backend.save_metadata(s);
            c.reply(nullptr);
            return true;
        }
        if (m == "Delete") {
            if (!backend.state(r.wallet).wallet)
                throw Error("Collection is locked", "org.freedesktop.Secret.Error.IsLocked");
            auto& s = backend.unlock(r.wallet, c.sender, "Secret Service application");
            s.wallet->folders[r.folder].erase(r.key);
            backend.save(s);
            s.metadata.erase(r.folder + "/" + r.key);
            backend.save_metadata(s);
            service.emit(collection_path(r.wallet), collection, "ItemDeleted", g_variant_new("(o)", c.path.c_str()));
            c.reply(g_variant_new("(o)", "/"));
            return true;
        }
        return false;
    }
    if (c.interface == "org.freedesktop.impl.portal.Secret" && m == "RetrieveSecret") {
        Variant owner(g_dbus_connection_call_sync(service.connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus", "GetNameOwner", g_variant_new("(s)", "org.freedesktop.portal.Desktop"),
            G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE, 3000, nullptr, nullptr));
        if (!owner.v || string_arg(owner.v, 0) != c.sender)
            throw Error("Only the desktop portal may request application secrets");
        auto app = string_arg(c.args, 1);
        auto h = child(c.args, 2);
        if (!g_variant_is_of_type(h.v, G_VARIANT_TYPE_HANDLE))
            throw Error("Invalid portal descriptor");
        auto* list = g_dbus_message_get_unix_fd_list(c.message);
        int fd = list ? g_unix_fd_list_get(list, g_variant_get_handle(h.v), nullptr) : -1;
        if (fd < 0)
            throw Error("Missing portal descriptor");
        try {
            auto& s = backend.unlock(backend.default_wallet(), c.sender, "Secret portal");
            auto& entries = s.wallet->folders["xdg-desktop-portal"];
            if (!entries.contains(app)) {
                Bytes value(64);
                gcry_randomize(value.data(), value.size(), GCRY_STRONG_RANDOM);
                entries[app] = { STREAM, std::move(value) };
                backend.save(s);
            }
            auto& value = entries.at(app).value;
            if (entries.at(app).type != STREAM || value.size() != 64)
                throw Error("Invalid application master secret");
            pollfd p { fd, POLLOUT, 0 };
            if (poll(&p, 1, 3000) <= 0 || write(fd, value.data(), value.size()) != ssize_t(value.size()))
                throw Error("Cannot deliver application secret");
            close(fd);
        } catch (...) {
            close(fd);
            throw;
        }
        GVariantBuilder results;
        g_variant_builder_init(&results, G_VARIANT_TYPE("a{sv}"));
        c.reply(g_variant_new("(u@a{sv})", 0u, g_variant_builder_end(&results)));
        return true;
    }
    return false;
}
}
