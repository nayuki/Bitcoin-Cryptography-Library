/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include <cstring>
#include "Sha256Hash.hpp"
#include "Utils.hpp"

using std::uint8_t;
using std::size_t;


Sha256Hash::Sha256Hash(const uint8_t hash[HASH_LEN], size_t len) {
	assert(hash != nullptr && len == HASH_LEN);
	std::memcpy(value, hash, sizeof(value));
}


Sha256Hash::Sha256Hash(const char *str) :
			value() {
	assert(str != nullptr && std::strlen(str) == HASH_LEN * 2);
	for (int i = 0; i < HASH_LEN * 2; i++) {
		int digit = Utils::parseHexDigit(str[HASH_LEN * 2 - 1 - i]);
		assert(digit != -1);
		value[i >> 1] |= digit << ((i & 1) << 2);
	}
}


bool Sha256Hash::operator==(const Sha256Hash &other) const {
	int diff = 0;
	for (int i = 0; i < HASH_LEN; i++)
		diff |= value[i] ^ other.value[i];
	return diff == 0;
}


bool Sha256Hash::operator!=(const Sha256Hash &other) const {
	return !(*this == other);
}
