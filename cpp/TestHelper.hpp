/* 
 * Helper definitions and functions for runnable test suite programs.
 * 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#undef NDEBUG
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

using std::size_t;
typedef std::vector<std::uint8_t> Bytes;


template <typename T, size_t N>
size_t arrayLength(const T (&array)[N]) {
	return N;
}


Bytes asciiBytes(const char *str) {
	Bytes result;
	size_t length = std::strlen(str);
	for (size_t i = 0; i < length; i++)
		result.push_back(static_cast<std::uint8_t>(str[i]));
	return result;
}


Bytes hexBytes(const char *str) {
	Bytes result;
	size_t length = std::strlen(str);
	assert(length % 2 == 0);
	length /= 2;
	for (size_t i = 0; i < length; i++) {
		unsigned int temp;
		std::sscanf(&str[i * 2], "%02x", &temp);
		result.push_back(static_cast<std::uint8_t>(temp));
	}
	return result;
}
