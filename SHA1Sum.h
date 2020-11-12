/**
    @file
    @copyright
        Copyright Bernd Amend 2016-2020
        Distributed under the Boost Software License, Version 1.0.
        (See accompanying file LICENSE_1_0.txt or copy at
        http://www.boost.org/LICENSE_1_0.txt)
*/
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

class SHA1Sum final {
public:
  SHA1Sum(const void *data_in, size_t length) {
    const unsigned char *data =
        reinterpret_cast<const unsigned char *>(data_in);

    uint32_t h0 = 0x67452301U, h1 = 0xefcdab89U, h2 = 0x98badcfeU,
                  h3 = 0x10325476U, h4 = 0xc3d2e1f0U;

    auto leftrotate = [](uint32_t value, uint32_t steps) {
      return (value << steps) | (value >> (32 - steps));
    };

    auto calc = [&](const unsigned char *bd) {
      std::array<uint32_t, 80> w;
#if __BYTE_ORDER == __LITTLE_ENDIAN
      for (std::size_t i = 0; i < 16; ++i)
        w[i] = fix_endian(*reinterpret_cast<const uint32_t *>(
            bd + sizeof(uint32_t) * i));
#elif __BYTE_ORDER == __BIG_ENDIAN
      std::memcpy(w.data(), reinterpret_cast<const uint32_t *>(bd),
                  16 * sizeof(uint32_t));
#endif

      auto a = h0, b = h1, c = h2, d = h3, e = h4;

      auto calc_w = [&](std::size_t i) {
        return w[i] =
                   leftrotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
      };

      auto round_func = [&](auto w, auto f, auto k) {
        const auto temp = leftrotate(a, 5) + f + e + k + w;
        e = d;
        d = c;
        c = leftrotate(b, 30);
        b = a;
        a = temp;
      };

      for (auto i = 0; i < 16; ++i)
        round_func(w[i], (b & c) | (~b & d), 0x5a827999U);
      for (auto i = 16; i < 20; ++i)
        round_func(calc_w(i), (b & c) | (~b & d), 0x5a827999U);
      for (auto i = 20; i < 40; ++i)
        round_func(calc_w(i), b ^ c ^ d, 0x6ed9eba1U);
      for (auto i = 40; i < 60; ++i)
        round_func(calc_w(i), (b & c) | (b & d) | (c & d), 0x8f1bbcdcU);
      for (auto i = 60; i < 80; ++i)
        round_func(calc_w(i), b ^ c ^ d, 0xca62c1d6U);

      h0 += a;
      h1 += b;
      h2 += c;
      h3 += d;
      h4 += e;
    };

    // process all complete 512-bit blocks
    const auto max_length = length - length % 64;
    for (size_t i = 0; i < max_length; i += 64)
      calc(data + i);

    // the last incomplete block
    std::array<unsigned char, 64> last_block{};
    auto i = length - max_length;
    std::memcpy(last_block.data(), data + max_length, i);
    last_block[i] = 0x80;
    if (i >= 56) {
      calc(last_block.data());
      last_block = {};
    }
    *reinterpret_cast<uint64_t *>(last_block.data() + 56) =
        fix_endian(static_cast<uint64_t>(length) * 8);
    calc(last_block.data());

    auto *out = reinterpret_cast<uint32_t *>(sum.data());
    out[0] = fix_endian(h0);
    out[1] = fix_endian(h1);
    out[2] = fix_endian(h2);
    out[3] = fix_endian(h3);
    out[4] = fix_endian(h4);
  }

  explicit SHA1Sum(const std::string &data)
      : SHA1Sum(data.c_str(), data.length()) {}

  inline std::string str() const {
    const std::string hex_digits = {"0123456789abcdef"};

    std::string result;
    result.reserve(40);

    for (const auto &i : sum) {
      result += hex_digits[i >> 4 & 0xf];
      result += hex_digits[i & 0xf];
    }
    return result;
  }

  inline std::array<unsigned char, 20> get_sum() const { return sum; }

private:
  std::array<unsigned char, 20> sum;

  static inline uint32_t fix_endian(uint32_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return ((val & 0x000000ffu) << 24) | ((val & 0x0000ff00u) << 8) |
           ((val & 0x00ff0000u) >> 8) | ((val & 0xff000000u) >> 24);
#else
    return val;
#endif
  }

  static inline uint64_t fix_endian(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return ((val & 0x00000000000000ffULL) << 56) |
           ((val & 0x000000000000ff00ULL) << 40) |
           ((val & 0x0000000000ff0000ULL) << 24) |
           ((val & 0x00000000ff000000ULL) << 8) |
           ((val & 0x000000ff00000000ULL) >> 8) |
           ((val & 0x0000ff0000000000ULL) >> 24) |
           ((val & 0x00ff000000000000ULL) >> 40) |
           ((val & 0xff00000000000000ULL) >> 56);
#else
    return val;
#endif
  }
};
