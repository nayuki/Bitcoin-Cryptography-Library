/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "Utils.hpp"


/* 
 * Represents a 32-byte SHA-256 hash value.
 * Instances of this class are immutable.
 * 
 * Note that by Bitcoin convention, SHA-256 hash strings are serialized in byte-reversed order.
 * For example, these three lines all represent the same hash value:
 * - Bigint: 0x0102030405060708091011121314151617181920212223242526272829303132.
 * - Byte array: {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
 *                0x17,0x18,0x19,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x30,0x31,0x32}.
 * - Hex string: "3231302928272625242322212019181716151413121110090807060504030201".
 */
#define SHA256_HASH_LEN 32
class Sha256Hash final {
	
	/* Fields */
	
private:
	uint8_t value[SHA256_HASH_LEN];
	
	
	
	/* Constructors */
public:
	
	// Constructs a Sha256Hash from the given array of 32 bytes (len is a dummy parameter that must equal 32).
	// Constant-time with respect to the given array of values.
	Sha256Hash(const uint8_t hash[SHA256_HASH_LEN], size_t len) {
		assert(hash != nullptr && len == SHA256_HASH_LEN);
		memcpy(value, hash, sizeof(value));
	}
	
	
	// Constructs a Sha256Hash from the given 64-character byte-reversed hexadecimal string. Not constant-time.
	Sha256Hash(const char *str) :
				value() {
		assert(str != nullptr && strlen(str) == SHA256_HASH_LEN * 2);
		for (int i = 0; i < SHA256_HASH_LEN * 2; i++) {
			int digit = Utils::parseHexDigit(str[SHA256_HASH_LEN * 2 - 1 - i]);
			assert(digit != -1);
			value[i >> 1] |= digit << ((i & 1) << 2);
		}
	}
	
	
	// Business as usual.
	Sha256Hash(const Sha256Hash &other) = default;
	Sha256Hash(Sha256Hash &&other) = default;
	
	
	
	/* Instance methods */
public:
	
	// Retrieves a single byte of the hash. Not constant-time with respect to the index.
	uint8_t getByte(int index) const {
		assert(0 <= index && index < SHA256_HASH_LEN);
		return value[index];
	}
	
	
	// Provides a read-only view of the underlying 32-byte array.
	const uint8_t *data() const {
		return &value[0];
	}
	
	
	// Tests whether the given hash is equal to this one. Constant-time with respect to both values.
	bool operator==(const Sha256Hash &other) const {
		uint8_t diff = 0;
		for (int i = 0; i < SHA256_HASH_LEN; i++)
			diff |= value[i] ^ other.value[i];
		return diff == 0;
	}
	
	
	// Tests whether the given hash is unequal to this one. Constant-time with respect to both values.
	bool operator!=(const Sha256Hash &other) const {
		return !(*this == other);
	}
	
	
	// Enforces immutability.
	Sha256Hash &operator=(const Sha256Hash &other) = delete;
	Sha256Hash &operator=(Sha256Hash &&other) = delete;
	
};
