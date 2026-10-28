// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "bus.hpp"
namespace dw {
struct Session {
    std::string owner;
    Bytes key;
};
struct Prompt {
    std::string owner;
    std::function<GVariant*()> action;
    bool running = false;
};
struct ItemRef {
    std::string wallet, folder, key;
};
struct Secrets {
    Service& service;
    std::map<std::string, Session> sessions;
    std::map<std::string, Prompt> prompts;
    int next_id = 1;
    explicit Secrets(Service& s)
        : service(s)
    {
    }
    bool call(Call&);
    void disconnect(const std::string&);
    void changed(const std::string&, const std::string&);
    std::vector<std::string> collections();
    std::string collection_path(const std::string&);
    std::string wallet_name(const std::string&);
    std::vector<std::string> items(const std::string&);
    ItemRef item_ref(const std::string&);
    std::string item_path(const ItemRef&);
    std::string prompt(const std::string&, std::function<GVariant*()>);
    GVariant* properties(const std::string&, const std::string&);
    GVariant* secret(const ItemRef&, const std::string&, const std::string&);
    Bytes decrypt(GVariant*, const std::string&);
    std::string mime(const ItemRef&);
    Json attributes(const ItemRef&);
    std::vector<std::string> search(const Json&, const std::string& wallet = "");
};
}
