// SPDX-License-Identifier: LGPL-2.0-or-later
#include "bus.hpp"
#include "introspection.hpp"
#include <algorithm>
namespace dw {
bool Service::wallet_call(Call& c)
{
    bool compat = c.interface == "org.kde.kwalletcompat" && c.path == "/ksecretd";
    if (!compat && (c.interface != "org.kde.KWallet" || c.path != "/modules/kwalletd6"))
        return false;
    auto& m = c.method;
    if (!wallet_signature(m, c.signature, compat))
        throw Error("Invalid KWallet method signature");
    auto integer = [&](int i) { c.reply(g_variant_new("(i)", i)); };
    auto boolean = [&](bool b) { c.reply(g_variant_new("(b)", b)); };
    auto string = [&](const std::string& s) { c.reply(g_variant_new("(s)", s.c_str())); };
    auto strings = [&](const std::vector<std::string>& s) { c.reply(g_variant_new("(@as)", strings_variant(s))); };
    if (m == "isEnabled") {
        boolean(backend.enabled());
        return true;
    }
    if (m == "wallets") {
        strings(backend.names());
        return true;
    }
    if (m == "networkWallet" || m == "localWallet") {
        string(backend.default_wallet(m == "localWallet"));
        return true;
    }
    if (m == "open") {
        try {
            integer(backend.open(string_arg(c.args, 0), c.sender, string_arg(c.args, 2)));
        } catch (const Error&) {
            integer(-1);
        }
        return true;
    }
    if (m == "openAsync") {
        int id = next_transaction++;
        struct Job {
            Service* self;
            int id;
            std::string wallet, owner, app;
        };
        auto* job = new Job { this, id, string_arg(c.args, 0), c.sender, string_arg(c.args, 2) };
        integer(id);
        g_idle_add(
            [](gpointer data) -> gboolean {
                std::unique_ptr<Job> j(static_cast<Job*>(data));
                int handle = -1;
                try {
                    handle = j->self->backend.open(j->wallet, j->owner, j->app);
                } catch (const std::exception&) {
                }
                j->self->emit("/modules/kwalletd6", "org.kde.KWallet", "walletAsyncOpened",
                    g_variant_new("(ii)", j->id, handle), j->owner.c_str());
                return G_SOURCE_REMOVE;
            },
            job);
        return true;
    }
    if (m == "isOpen") {
        if (c.signature == "s") {
            auto it = backend.states.find(string_arg(c.args, 0));
            boolean(it != backend.states.end() && it->second.wallet);
        } else {
            int id = integer_arg(c.args, 0);
            auto it = backend.handles.find(id);
            boolean(it != backend.handles.end() && it->second.owner == c.sender
                && backend.states.at(it->second.wallet).wallet);
        }
        return true;
    }
    if (m == "close") {
        try {
            if (c.signature == "sb")
                backend.lock(string_arg(c.args, 0));
            else
                backend.close(integer_arg(c.args, 0), c.sender, string_arg(c.args, 2));
            integer(0);
        } catch (const Error&) {
            integer(-1);
        }
        return true;
    }
    if (m == "deleteWallet") {
        try {
            backend.erase(string_arg(c.args, 0));
            integer(0);
        } catch (const Error&) {
            integer(-1);
        }
        return true;
    }
    if (m == "changePassword") {
        backend.password(string_arg(c.args, 0), c.sender, string_arg(c.args, 2));
        c.reply(nullptr);
        return true;
    }
    if (m == "reconfigure") {
        c.reply(nullptr);
        return true;
    }
    if (m == "closeAllWallets") {
        std::vector<std::string> names;
        for (auto& [name, s] : backend.states)
            names.push_back(name);
        for (auto& name : names)
            backend.lock(name);
        emit(c.path, "org.kde.KWallet", "allWalletsClosed", g_variant_new("()"));
        c.reply(nullptr);
        return true;
    }
    if (m == "users") {
        auto name = string_arg(c.args, 0);
        std::set<std::string> users;
        for (auto& [id, h] : backend.handles)
            if (h.wallet == name)
                users.insert(h.app);
        strings({ users.begin(), users.end() });
        return true;
    }
    if (m == "disconnectApplication") {
        auto name = string_arg(c.args, 0), app = string_arg(c.args, 1);
        bool removed = false;
        for (auto it = backend.handles.begin(); it != backend.handles.end();) {
            if (it->second.wallet == name && it->second.app == app && it->second.owner == c.sender) {
                it = backend.handles.erase(it);
                removed = true;
            } else
                ++it;
        }
        boolean(removed);
        return true;
    }
    if (m == "folderDoesNotExist" || m == "keyDoesNotExist") {
        auto& s = backend.state(string_arg(c.args, 0));
        if (!s.wallet) {
            boolean(false);
            return true;
        }
        auto folder = string_arg(c.args, 1);
        bool absent = !s.wallet->folders.contains(folder);
        if (m == "keyDoesNotExist" && !absent)
            absent = !s.wallet->folders.at(folder).contains(string_arg(c.args, 2));
        boolean(absent);
        return true;
    }
    size_t count = g_variant_n_children(c.args);
    auto app = string_arg(c.args, count - 1);
    auto& s = backend.access(integer_arg(c.args, 0), c.sender, app);
    auto& folders = s.wallet->folders;
    if (m == "sync") {
        backend.save(s);
        c.reply(nullptr);
        return true;
    }
    if (m == "folderList") {
        std::vector<std::string> out;
        for (auto& [name, entries] : folders)
            out.push_back(name);
        strings(out);
        return true;
    }
    auto folder = string_arg(c.args, 1);
    if (m == "hasFolder") {
        boolean(folders.contains(folder));
        return true;
    }
    if (m == "createFolder") {
        bool added = folders.try_emplace(folder).second;
        if (added)
            backend.save(s);
        boolean(added);
        return true;
    }
    if (m == "removeFolder") {
        bool removed = folders.erase(folder);
        if (removed)
            backend.save(s);
        boolean(removed);
        return true;
    }
    if (!folders.contains(folder))
        throw Error("Wallet folder does not exist");
    auto& entries = folders.at(folder);
    if (m == "entryList") {
        std::vector<std::string> out;
        for (auto& [key, e] : entries)
            out.push_back(key);
        strings(out);
        return true;
    }
    if (m == "readEntryList" || m == "entriesList" || m == "readMapList" || m == "mapList" || m == "readPasswordList"
        || m == "passwordList") {
        bool filter = count == 4;
        auto pattern = filter ? string_arg(c.args, 2) : "*";
        GVariantBuilder b;
        g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
        for (auto& [name, e] : entries) {
            if (!g_pattern_match_simple(pattern.c_str(), name.c_str()))
                continue;
            bool password = m == "readPasswordList" || m == "passwordList", map = m == "readMapList" || m == "mapList";
            if ((password && e.type != PASSWORD) || (map && e.type != MAP))
                continue;
            GVariant* v = password ? g_variant_new_string(password_text(e).c_str()) : bytes_variant(e.value);
            g_variant_builder_add(&b, "{sv}", name.c_str(), v);
        }
        c.reply(g_variant_new("(@a{sv})", g_variant_builder_end(&b)));
        return true;
    }
    auto key = string_arg(c.args, 2);
    auto it = entries.find(key);
    if (m == "hasEntry") {
        boolean(it != entries.end());
        return true;
    }
    if (m == "entryType") {
        integer(it == entries.end() ? 0 : it->second.type);
        return true;
    }
    if (m == "renameEntry") {
        auto name = string_arg(c.args, 3);
        if (it == entries.end() || entries.contains(name)) {
            integer(-1);
            return true;
        }
        auto old = entries.extract(it);
        old.key() = name;
        entries.insert(std::move(old));
        backend.save(s);
        auto meta = folder + "/" + key;
        if (s.metadata.contains(meta)) {
            s.metadata[folder + "/" + name] = s.metadata[meta];
            s.metadata.erase(meta);
            backend.save_metadata(s);
        }
        integer(0);
        return true;
    }
    if (m == "removeEntry") {
        bool removed = entries.erase(key);
        if (removed) {
            backend.save(s);
            s.metadata.erase(folder + "/" + key);
            backend.save_metadata(s);
        }
        integer(removed ? 0 : -1);
        return true;
    }
    if (m == "writePassword" || m == "writeMap" || m == "writeEntry") {
        Entry e;
        if (m == "writePassword") {
            e.type = PASSWORD;
            std::string text = string_arg(c.args, 3);
            e.value = password_value(text);
            explicit_bzero(text.data(), text.size());
        } else {
            e.type = m == "writeMap" ? MAP : count == 6 ? integer_arg(c.args, 4) : STREAM;
            if (e.type < PASSWORD || e.type > MAP)
                throw Error("Unsupported entry type");
            auto data = child(c.args, 3);
            e.value = byte_array(data.v);
            if (e.type == MAP)
                (void)map_text(e);
            if (e.type == PASSWORD)
                (void)password_text(e);
        }
        entries[key] = std::move(e);
        backend.save(s);
        integer(0);
        return true;
    }
    if (it == entries.end())
        throw Error("Wallet entry not found");
    if (m == "readPassword") {
        string(password_text(it->second));
        return true;
    }
    if (m == "readMap" || m == "readEntry") {
        if (m == "readMap" && it->second.type != MAP)
            throw Error("Not a map entry");
        c.reply(g_variant_new("(@ay)", bytes_variant(it->second.value)));
        return true;
    }
    return false;
}
}
