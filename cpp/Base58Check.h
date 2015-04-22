/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstdint>
#include <cstring>
#include "Sha256.h"
#include "Sha256Hash.h"


/* 
 * Converts a sequence of 20 bytes (pubkey hash) into a Base58Check ASCII string.
 * Provides just one static method.
 */
class Base58Check {
	
public:
	// The outStr array must have length >= 35 (including null terminator). Not constant-time.
	static void pubkeyHashToBase58Check(const uint8_t pubkeyHash[20], char *outStr) {
		// Form the initial 21 bytes
		const int FINAL_LEN = 25;
		uint8_t bytesToEncode[FINAL_LEN];
		bytesToEncode[0] = 0;  // Version byte
		memcpy(&bytesToEncode[1], pubkeyHash, 20);
		
		// Compute and append final 4 bytes
		Sha256Hash sha256Hash = Sha256::getDoubleHash(bytesToEncode, 21);
		for (int i = 0; i < 4; i++)
			bytesToEncode[i + 21] = sha256Hash.getByte(i);
		
		// Count leading zero bytes
		int leadingZeros = 0;
		for (int i = 0; i < FINAL_LEN && bytesToEncode[i] == 0; i++)
			leadingZeros++;
		
		// Encode to Base 58
		int outLen = 0;
		while (!isZero(bytesToEncode, FINAL_LEN)) {
			outStr[outLen] = ALPHABET[mod58(bytesToEncode, FINAL_LEN)];
			outLen++;
			uint8_t quotient[FINAL_LEN];
			divide58(bytesToEncode, quotient, FINAL_LEN);
			memcpy(bytesToEncode, quotient, FINAL_LEN);
		}
		for (int i = 0; i < leadingZeros; i++) {
			outStr[outLen] = ALPHABET[0];
			outLen++;
		}
		outStr[outLen] = '\0';
		
		// Reverse string
		for (int i = 0, j = outLen - 1; i < j; i++, j--) {
			char temp = outStr[i];
			outStr[i] = outStr[j];
			outStr[j] = temp;
		}
	}
	
	
	
	/* Unsigned big-endian arbitrary-precision arithmetic functions */
	// Note: This differs from Uint256 because Uint256 is fixed-width, little-endian, and 32-bit-word-oriented.
private:
	
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
