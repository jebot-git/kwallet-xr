// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "wallet.hpp"
#include <functional>
#include <optional>
namespace dw {
std::optional<Bytes> pinentry(
    const std::string& title, const std::string& description, bool confirm = false, bool repeat = false);
void harden();
bool prompt_active();
void cancel_prompt();
void prompt_finished(std::function<void()>);
}
