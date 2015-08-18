/* 
 * Helper definitions and functions for runnable test suite programs.
 * 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

typedef std::vector<uint8_t> Bytes;

#define ARRAY_LENGTH(name)  (sizeof(name) / sizeof(name[0]))


Bytes asciiBytes(const char *str) {
	Bytes result;
	size_t length = strlen(str);
	for (size_t i = 0; i < length; i++)
		result.push_back(static_cast<uint8_t>(str[i]));
	return result;
}


Bytes hexBytes(const char *str) {
	Bytes result;
	size_t length = strlen(str);
	assert(length % 2 == 0);
	length /= 2;
	for (size_t i = 0; i < length; i++) {
		int temp;
		sscanf(&str[i * 2], "%02x", &temp);
		result.push_back(static_cast<uint8_t>(temp));
	}
	return result;
}
