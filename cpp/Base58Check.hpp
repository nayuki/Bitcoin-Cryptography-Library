/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstdint>
#include <cstring>
#include "Ripemd160.hpp"
#include "Sha256.hpp"
#include "Sha256Hash.hpp"
#include "Uint256.hpp"


/* 
 * Converts a pubkey hash or a private key into a Base58Check ASCII string.
 * Provides just two static methods.
 */
class Base58Check {
	
public:
	
	// Exports the given 20-byte public key hash as a public address.
	// The outStr array must have length >= 35 (including null terminator).
	// The output text length is between 25 and 34 characters, inclusive. Not constant-time.
	static void pubkeyHashToBase58Check(const uint8_t pubkeyHash[RIPEMD160_HASH_LEN], char outStr[35]) {
		uint8_t toEncode[1 + RIPEMD160_HASH_LEN + 4] = {};
		toEncode[0] = 0x00;  // Version byte
		memcpy(&toEncode[1], pubkeyHash, RIPEMD160_HASH_LEN);
		bytesToBase58Check(toEncode, static_cast<int>(sizeof(toEncode) - 4), outStr);
	}
	
	
	// Exports the given private key as compressed WIF.
	// The outStr array must have length >= 53 (including null terminator).
	// The output text length is always 52 characters. Not constant-time.
	static void privateKeyToBase58Check(const Uint256 &privKey, char outStr[53]) {
		uint8_t toEncode[1 + 32 + 1 + 4] = {};
		toEncode[0] = 0x80;  // Version byte
		privKey.getBigEndianBytes(&toEncode[1]);
		toEncode[33] = 0x01;  // Compressed marker
		bytesToBase58Check(toEncode, static_cast<int>(sizeof(toEncode) - 4), outStr);
	}
	
	
private:
	
	// Computes the 4-byte hash and converts the concatenated data to Base58Check.
	// This overwrites data[0 <= i < len + 4]. The caller is responsible for the prefix byte,
	// 4 free bytes starting at data[len], and allocating enough space in outStr. Not constant-time.
	static void bytesToBase58Check(uint8_t *data, int len, char *outStr) {
		// Append 4-byte hash
		#define MAX_TOTAL_BYTES 38  // Including the 4-byte hash
		assert(0 <= len && len <= MAX_TOTAL_BYTES - 4);
		Sha256Hash sha256Hash = Sha256::getDoubleHash(data, len);
		for (int i = 0; i < 4; i++, len++)
			data[len] = sha256Hash.getByte(i);
		
		// Count leading zero bytes
		int leadingZeros = 0;
		for (int i = 0; i < len && data[i] == 0; i++)
			leadingZeros++;
		
		// Encode to Base 58
		int outLen = 0;
		while (!isZero(data, len)) {  // Extract digits in little-endian
			outStr[outLen] = ALPHABET[mod58(data, len)];
			outLen++;
			uint8_t quotient[MAX_TOTAL_BYTES] = {};
			divide58(data, quotient, len);  // quotient = floor(data / 58)
			memcpy(data, quotient, len);  // data = quotient
		}
		for (int i = 0; i < leadingZeros; i++) {  // Append leading zeros
			outStr[outLen] = ALPHABET[0];
			outLen++;
		}
		outStr[outLen] = '\0';
		
		// Reverse the string
		for (int i = 0, j = outLen - 1; i < j; i++, j--) {
			char temp = outStr[i];
			outStr[i] = outStr[j];
			outStr[j] = temp;
		}
		#undef MAX_TOTAL_BYTES
	}
	
	
	/* Unsigned big-endian arbitrary-precision arithmetic functions */
	// Note: This differs from Uint256 because Uint256 is fixed-width, little-endian, and 32-bit-word-oriented.
	
	// Tests whether the given bigint is zero. Not constant-time.
	static bool isZero(const uint8_t *x, int len) {
		for (int i = 0; i < len; i++) {
			if (x[i] != 0)
				return false;
		}
		return true;
	}
	
	
	// Returns the given bigint modulo 58. Not constant-time.
	static uint8_t mod58(const uint8_t *x, int len) {
		uint_fast16_t sum = 0;
		for (int i = 0; i < len; i++)
			sum = ((sum * 24) + x[i]) % 58;  // Note: 256 % 58 = 24
		return static_cast<uint8_t>(sum);
	}
	
	
	// Computes the quotient y = floor(x / 58). Not constant-time.
	static void divide58(const uint8_t *x, uint8_t *y, int len) {
		memset(y, 0, len);
		uint_fast16_t dividend = 0;
		for (int i = 0; i < len * 8; i++) {  // For each output bit
			dividend = (dividend << 1) | ((x[i >> 3] >> (7 - (i & 7))) & 1);  // Shift next input bit into right side
			if (dividend >= 58) {
				dividend -= 58;
				y[i >> 3] |= 1 << (7 - (i & 7));
			}
		}
	}
	
	
	Base58Check() {}  // Not instantiable
	
	
	
	/* Class constants */
	
	static const char *ALPHABET;
	
};

// Static initializers
const char *Base58Check::ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
