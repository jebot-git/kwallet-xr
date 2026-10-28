// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "prompt.hpp"
#include "wallet.hpp"
#include <chrono>
#include <functional>
#include <gio/gio.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <set>
namespace dw {
using Json = nlohmann::json;
struct State {
    std::chrono::steady_clock::time_point last_access = std::chrono::steady_clock::now();
    std::string name;
    std::unique_ptr<Wallet> wallet;
    std::set<std::string> owners;
    Json metadata;
};
struct Handle {
    std::string wallet, owner, app;
};
struct Backend {
    std::filesystem::path root;
    std::map<std::string, State> states;
    std::map<int, Handle> handles;
    int next_handle = 1;
    GDBusConnection* connection = nullptr;
    std::function<void(const std::string&, const std::string&)> changed;
    explicit Backend(std::filesystem::path);
    std::vector<std::string> names() const;
    bool enabled() const;
    void idle_close();
    std::string default_wallet(bool local = false) const;
    State& state(const std::string&);
    State& unlock(const std::string&, const std::string&, const std::string&);
    State& access(int, const std::string&, const std::string&);
    int open(const std::string&, const std::string&, const std::string&);
    void lock(const std::string&);
    void close(int, const std::string&, const std::string&);
    void disconnect(const std::string&);
    void save(State&);
    void erase(const std::string&);
    void password(const std::string&, const std::string&, const std::string&);
    std::filesystem::path filename(const std::string&) const;
    void save_metadata(State&);
};
}
