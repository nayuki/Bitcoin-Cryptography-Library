/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstdint>
#include "Ripemd160.hpp"
#include "Uint256.hpp"


/* 
 * Converts a pubkey hash or a private key into a Base58Check ASCII string.
 * Provides just two static methods.
 */
class Base58Check final {
	
public:
	
	// Exports the given 20-byte public key hash as a public address.
	// The outStr array must have length >= 35 (including null terminator).
	// The output text length is between 25 and 34 characters, inclusive. Not constant-time.
	static void pubkeyHashToBase58Check(const uint8_t pubkeyHash[RIPEMD160_HASH_LEN], char outStr[35]);
	
	
	// Exports the given private key as compressed WIF.
	// The outStr array must have length >= 53 (including null terminator).
	// The output text length is always 52 characters. Not constant-time.
	static void privateKeyToBase58Check(const Uint256 &privKey, char outStr[53]);
	
	
private:
	
	// Computes the 4-byte hash and converts the concatenated data to Base58Check.
	// This overwrites data[0 <= i < len + 4]. The caller is responsible for the prefix byte,
	// 4 free bytes starting at data[len], and allocating enough space in outStr. Not constant-time.
	static void bytesToBase58Check(uint8_t *data, int len, char *outStr);
	
	
	/* Unsigned big-endian arbitrary-precision arithmetic functions */
	// Note: This differs from Uint256 because Uint256 is fixed-width, little-endian, and 32-bit-word-oriented.
	
	// Tests whether the given bigint is zero. Not constant-time.
	static bool isZero(const uint8_t *x, int len);
	
	
	// Returns the given bigint modulo 58. Not constant-time.
	static uint8_t mod58(const uint8_t *x, int len);
	
	
	// Computes the quotient y = floor(x / 58). Not constant-time.
	static void divide58(const uint8_t *x, uint8_t *y, int len);
	
	
	Base58Check();  // Not instantiable
	
	
	
	/* Class constants */
	
	static const char *ALPHABET;
	
};
