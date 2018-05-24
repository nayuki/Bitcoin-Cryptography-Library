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
#include "Ripemd160.hpp"
#include "Uint256.hpp"


/* 
 * Converts a pubkey hash or a private key into a Base58Check ASCII string.
 * Provides just two static methods.
 */
class Base58Check final {
	
	// Exports the given 20-byte public key hash as a public address.
	// The outStr array must have length >= 35 (including null terminator).
	// The output text length is between 25 and 34 characters, inclusive. Not constant-time.
	public: static void pubkeyHashToBase58Check(uint8_t version, const std::uint8_t pubkeyHash[Ripemd160::HASH_LEN], char outStr[35]);
	public: static void pubkeyHashToBase58Check(const std::uint8_t pubkeyHash[Ripemd160::HASH_LEN], char outStr[35]) {
		pubkeyHashToBase58Check(0x00, pubkeyHash, outStr);
	}
	
	
	// Exports the given private key as compressed WIF using the given version byte and given compression flag
	// The outStr array must have length >= 53 (including null terminator).
	// The output text length is always 52 characters. Not constant-time.
	public: static void privateKeyToBase58Check(uint8_t version, bool compressed, const Uint256 &privKey, char outStr[53]);

	// Exports the given private key as compressed WIF using the default bitcoin version byte in a compressed format
	// The outStr array must have length >= 53 (including null terminator).
	// The output text length is always 52 characters. Not constant-time.
	public: static void privateKeyToBase58Check(const Uint256 &privKey, char outStr[53]) {
		privateKeyToBase58Check(0x80, true, privKey, outStr);
	}
	
	
	// Parses the given public address string. If the syntax and check digits are correct,
	// then the output array is set to the decoded value and true is returned.
	// Otherwise the output array is unchanged and false is returned. Not constant-time.
	public: static bool pubkeyHashFromBase58Check(const char *addrStr, std::uint8_t outPubkeyHash[Ripemd160::HASH_LEN]);
	
	
	// Parses the given compressed WIF string. If the syntax and check digits are correct,
	// then the private key Uint256 is set to the decoded value and true is returned.
	// Otherwise the Uint256 is unchanged and false is returned. Not constant-time.
	// Note that the decoded integer may be outside the normal private key range of [1, CurvePoint::ORDER).
	public: static bool privateKeyFromBase58Check(const char wifStr[53], Uint256 &outPrivKey);

	// Parses the given compressed WIF string. If the syntax and check digits are correct,
	// then the private key Uint256 is set to the decoded value and true is returned.
	// Otherwise the Uint256 is unchanged and false is returned. Not constant-time.
	// version is set to the WIF version byte and compressed is set to true if the address was compressed
	// Note that the decoded integer may be outside the normal private key range of [1, CurvePoint::ORDER).
	public: static bool privateKeyFromBase58Check(const char wifStr[53], Uint256 &outPrivKey, uint8_t& version, bool& compressed);
	
	
	// Computes the 4-byte hash and converts the concatenated data to Base58Check.
	// This overwrites data[0 <= i < len + 4]. The caller is responsible for the prefix byte,
	// 4 free bytes starting at data[len], and allocating enough space in outStr. Not constant-time.
	private: static void bytesToBase58Check(std::uint8_t data[], std::size_t dataLen, char *outStr);
	
	
	// Converts the given Base58Check string to an array of bytes. Returns true if the conversion succeeded;
	// otherwise returns false if the string contains non-Base58 characters, decodes to
	// shorter or longer data than the output array length, or fails the hash check.
	// The output array elements may be changed even if false is returned. Not constant-time.
	private: static bool base58CheckToBytes(const char *inStr, std::uint8_t outData[], std::size_t outDataLen);
	
	
	/* Unsigned big-endian arbitrary-precision arithmetic functions */
	// Note: This differs from Uint256 because Uint256 is fixed-width, little-endian, and 32-bit-word-oriented.
	
	// Tests whether the given bigint is zero. Not constant-time.
	private: static bool isZero(const std::uint8_t x[], std::size_t len);
	
	
	// Returns the given bigint modulo 58. Not constant-time.
	private: static std::uint8_t mod58(const std::uint8_t x[], std::size_t len);
	
	
	// Computes the quotient y = floor(x / 58). Not constant-time.
	private: static void divide58(const std::uint8_t x[], std::uint8_t y[], std::size_t len);
	
	
	// Computes the sum (x = (x + y) mod 256^len) in place. Returns whether the
	// carry-out is non-zero. Constant-time with respect to x's values and the value of y.
	private: static bool addUint8(std::uint8_t x[], std::uint8_t y, std::size_t len);
	
	
	// Computes the product (x = (x * 58) mod 256^len) in place. Returns whether
	// the carry-out is non-zero. Constant-time with respect to x's values.
	private: static bool multiply58(std::uint8_t x[], std::size_t len);
	
	
	private: Base58Check();  // Not instantiable
	
	
	
	/*---- Class constants ----*/
	
	public: static const char *ALPHABET;
	
};
