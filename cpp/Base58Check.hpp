/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
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
	
	
	// Parses the given public address string. If the syntax and check digits are correct,
	// then the output array is set to the decoded value and true is returned.
	// Otherwise the output array is unchanged and false is returned. Not constant-time.
	static bool pubkeyHashFromBase58Check(const char *addrStr, uint8_t outPubkeyHash[RIPEMD160_HASH_LEN]);
	
	
	// Parses the given compressed WIF string. If the syntax and check digits are correct,
	// then the private key Uint256 is set to the decoded value and true is returned.
	// Otherwise the Uint256 is unchanged and false is returned. Not constant-time.
	// Note that the decoded integer may be outside the normal private key range of [1, CurvePoint::ORDER).
	static bool privateKeyFromBase58Check(const char wifStr[53], Uint256 &outPrivKey);
	
	
private:
	
	// Computes the 4-byte hash and converts the concatenated data to Base58Check.
	// This overwrites data[0 <= i < len + 4]. The caller is responsible for the prefix byte,
	// 4 free bytes starting at data[len], and allocating enough space in outStr. Not constant-time.
	static void bytesToBase58Check(uint8_t *data, size_t dataLen, char *outStr);
	
	
	// Converts the given Base58Check string to an array of bytes. Returns true if the conversion succeeded;
	// otherwise returns false if the string contains non-Base58 characters, decodes to
	// shorter or longer data than the output array length, or fails the hash check.
	// The output array elements may be changed even if false is returned. Not constant-time.
	static bool base58CheckToBytes(const char *inStr, uint8_t *outData, size_t outDataLen);
	
	
	/* Unsigned big-endian arbitrary-precision arithmetic functions */
	// Note: This differs from Uint256 because Uint256 is fixed-width, little-endian, and 32-bit-word-oriented.
	
	// Tests whether the given bigint is zero. Not constant-time.
	static bool isZero(const uint8_t *x, size_t len);
	
	
	// Returns the given bigint modulo 58. Not constant-time.
	static uint8_t mod58(const uint8_t *x, size_t len);
	
	
	// Computes the quotient y = floor(x / 58). Not constant-time.
	static void divide58(const uint8_t *x, uint8_t *y, size_t len);
	
	
	// Computes the sum (x = (x + y) mod 256^len) in place. Returns whether the
	// carry-out is non-zero. Constant-time with respect to x's values and the value of y.
	static bool addUint8(uint8_t *x, uint8_t y, size_t len);
	
	
	// Computes the product (x = (x * 58) mod 256^len) in place. Returns whether
	// the carry-out is non-zero. Constant-time with respect to x's values.
	static bool multiply58(uint8_t *x, size_t len);
	
	
	Base58Check();  // Not instantiable
	
	
	
	/*---- Class constants ----*/
	
public:
	static const char *ALPHABET;
	
};
