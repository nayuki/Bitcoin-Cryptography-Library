/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include <cstring>
#include "Sha256Hash.hpp"
#include "Utils.hpp"


Sha256Hash::Sha256Hash(const uint8_t hash[SHA256_HASH_LEN], size_t len) {
	assert(hash != nullptr && len == SHA256_HASH_LEN);
	memcpy(value, hash, sizeof(value));
}


Sha256Hash::Sha256Hash(const char *str) :
			value() {
	assert(str != nullptr && strlen(str) == SHA256_HASH_LEN * 2);
	for (int i = 0; i < SHA256_HASH_LEN * 2; i++) {
		int digit = Utils::parseHexDigit(str[SHA256_HASH_LEN * 2 - 1 - i]);
		assert(digit != -1);
		value[i >> 1] |= digit << ((i & 1) << 2);
	}
}


uint8_t Sha256Hash::getByte(int index) const {
	assert(0 <= index && index < SHA256_HASH_LEN);
	return value[index];
}


const uint8_t *Sha256Hash::data() const {
	return &value[0];
}


bool Sha256Hash::operator==(const Sha256Hash &other) const {
	uint8_t diff = 0;
	for (int i = 0; i < SHA256_HASH_LEN; i++)
		diff |= value[i] ^ other.value[i];
	return diff == 0;
}


bool Sha256Hash::operator!=(const Sha256Hash &other) const {
	return !(*this == other);
}
