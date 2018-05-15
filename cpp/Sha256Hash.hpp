/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstddef>
#include <cstdint>


/* 
 * Represents a 32-byte SHA-256 hash value.
 * 
 * Note that by Bitcoin convention, SHA-256 hash strings are serialized in byte-reversed order.
 * For example, these three lines all represent the same hash value:
 * - Bigint: 0x0102030405060708091011121314151617181920212223242526272829303132.
 * - Byte array: {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
 *                0x17,0x18,0x19,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x30,0x31,0x32}.
 * - Hex string: "3231302928272625242322212019181716151413121110090807060504030201".
 */
class Sha256Hash final {
	
	public: static constexpr int HASH_LEN = 32;
	
	/*---- Fields ----*/
	
	public: std::uint8_t value[HASH_LEN];
	
	
	
	/*---- Constructors ----*/
	
	// Constructs a Sha256Hash from the given array of 32 bytes (len is a dummy parameter that must equal 32).
	// Constant-time with respect to the given array of values.
	public: explicit Sha256Hash(const std::uint8_t hash[HASH_LEN], std::size_t len);
	
	
	// Constructs a Sha256Hash from the given 64-character byte-reversed hexadecimal string. Not constant-time.
	public: explicit Sha256Hash(const char *str);
	
	
	
	/*---- Instance methods ----*/
	
	// Tests whether the given hash is equal to this one. Constant-time with respect to both values.
	public: bool operator==(const Sha256Hash &other) const;
	
	
	// Tests whether the given hash is unequal to this one. Constant-time with respect to both values.
	public: bool operator!=(const Sha256Hash &other) const;
	
};
