/**
    @file
    @copyright
        Copyright Bernd Amend 2016-2017
        Distributed under the Boost Software License, Version 1.0.
        (See accompanying file LICENSE_1_0.txt or copy at
        http://www.boost.org/LICENSE_1_0.txt)
*/
#include "SHA1Sum.h"
#include <iostream>

using namespace std;

int main() {
  if (SHA1Sum("The quick brown fox jumps over the lazy dog").str() !=
      "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") {
    return -1;
  }

  if (SHA1Sum("The quick brown fox jumps over the lazy cog").str() !=
      "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3") {
    return -2;
  }

  if (SHA1Sum("").str() != "da39a3ee5e6b4b0d3255bfef95601890afd80709") {
    cout << "fail\n";
    return -3;
  }

  if (SHA1Sum("1234567812345678123456781234567812345678123456781234567812345678"
              "1234567812345678123456781234567812345678123456781234567812345678"
              "1234567812345678123456781234567812345678123456781234567812345678"
              "1234567812345678123456781234567812345678123456781234567812345678"
              "123456781234567812345678123456781234567812345678123456781234567"
              "8")
          .str() != "885a054cf89870349842eee003e08401d5a73136") {
    return -4;
  }
  return 0;
}
