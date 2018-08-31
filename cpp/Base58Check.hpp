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
#include "ExtendedPrivateKey.hpp"
#include "Ripemd160.hpp"
#include "Uint256.hpp"


/* 
 * Converts a pubkey hash, private key, or extended private key to and from a Base58Check ASCII string.
 */
class Base58Check final {
	
	/*---- Public export-to-string functions ----*/
	
	// Exports the given 20-byte public key hash with the given version prefix byte as a public address.
	// The outStr array must have length >= 36 (including null terminator).
	// The output text length is between 25 and 35 characters, inclusive. Not constant-time.
	public: static void pubkeyHashToBase58Check(const std::uint8_t pubkeyHash[Ripemd160::HASH_LEN], std::uint8_t version, char outStr[36]);
	
	
	// Exports the given private key with the given version prefix byte as WIF.
	// The isCompressed parameter controls whether the private key should generate a compressed
	// public curve point, and should almost always be set to true (except for legacy applications).
	// The outStr array must have length >= 53 (including null terminator).
	// The output text length is between 38 and 52 characters, inclusive. Not constant-time.
	public: static void privateKeyToBase58Check(const Uint256 &privKey, std::uint8_t version, bool isCompressed, char outStr[53]);
	
	
	// Exports the given extended private key with the Bitcoin header and version prefix byte.
	// The outStr array must have length >= 112 (including null terminator).
	// The output text length is always 111 characters. Not constant-time.
	public: static void extendedPrivateKeyToBase58Check(const ExtendedPrivateKey &key, char outStr[112]);
	
	
	/*---- Public import-from-string functions ----*/
	
	// Parses the given public address string. If the syntax and check digits are correct, then the
	// output array is set to the decoded value, the version byte is set if not null, and true is returned.
	// Otherwise the output array and version are unchanged, and false is returned. Not constant-time.
	public: static bool pubkeyHashFromBase58Check(const char *addrStr, std::uint8_t outPubkeyHash[Ripemd160::HASH_LEN], std::uint8_t *outVersion);
	
	
	// Parses the given WIF string. If the syntax, optional compressed marker, and check digits are correct,
	// then the private key Uint256 is set to the decoded value, the version byte is set if not null,
	// the compressed status is set if not null, and true is returned. Otherwise the Uint256,
	// version, and compressed status are unchanged, and false is returned. Not constant-time.
	// Note that the decoded integer may be outside the normal private key range of [1, CurvePoint::ORDER).
	public: static bool privateKeyFromBase58Check(const char wifStr[53], Uint256 &outPrivKey, std::uint8_t *outVersion, bool *outIsCompressed);
	
	
	// Parses the given extended private key string. If the syntax and check digits are correct,
	// then the extended private key object is set to the decoded value, and true is returned.
	// Otherwise the object is unchanged, and false is returned. Not constant-time.
	public: static bool extendedPrivateKeyFromBase58Check(const char xprvStr[112], ExtendedPrivateKey &outKey);
	
	
	
	/*---- Private high-level Base58Check functions ----*/
	
	// Computes the 4-byte hash of the given byte array, concatenates it, and converts it to Base58Check.
	// This overwrites data and temp for indices 0 <= i < len+4. The caller is responsible for leaving 4 free bytes
	// starting at data[len], allocating len+4 bytes for temp, and allocating enough space in outStr. Not constant-time.
	private: static void bytesToBase58Check(std::uint8_t data[], std::uint8_t temp[], std::size_t dataLen, char *outStr);
	
	
	// Converts the given Base58Check string to an array of bytes. Returns true if the conversion succeeded;
	// otherwise returns false if the string contains non-Base58 characters, decodes to
	// shorter or longer data than the output array length, or fails the hash check.
	// The output array elements may be changed even if false is returned. Not constant-time.
	private: static bool base58CheckToBytes(const char *inStr, std::uint8_t outData[], std::size_t outDataLen);
	
	
	
	/*---- Private low-level arithmetic functions ----*/
	
	// These functions perform unsigned big-endian arbitrary-precision arithmetic on byte arrays that represent numbers.
	// These algorithms differ from Uint256 because Uint256 is fixed-width, little-endian, and 32-bit-word-oriented.
	
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
	
	
	
	/*---- Miscellaneous ----*/
	
	Base58Check() = delete;  // Not instantiable
	
	
	public: static const char *ALPHABET;
	
};
