// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "wallet.hpp"
namespace dw {
std::pair<Bytes, Bytes> negotiate(std::span<const unsigned char> client);
Bytes aes_encrypt(
    std::span<const unsigned char> key, std::span<const unsigned char> iv, std::span<const unsigned char> value);
Bytes aes_decrypt(
    std::span<const unsigned char> key, std::span<const unsigned char> iv, std::span<const unsigned char> value);
}
