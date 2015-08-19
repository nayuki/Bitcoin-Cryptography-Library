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
#include "Sha256Hash.hpp"


/* 
 * Computes the SHA-256 hash of a sequence of bytes, returning a Sha256Hash object.
 * Provides three static methods, and an instantiable stateful hasher.
 */
#define SHA256_BLOCK_LEN 64
class Sha256 final {
	
	/* Static functions */
	
public:
	
	static Sha256Hash getHash(const uint8_t *msg, size_t len) {
		assert(msg != nullptr || len == 0);
		return getHash(msg, len, INITIAL_STATE, 0);
	}
	
	
	static Sha256Hash getDoubleHash(const uint8_t *msg, size_t len) {
		assert(msg != nullptr || len == 0);
		Sha256Hash innerHash(getHash(msg, len));
		return getHash(innerHash.data(), SHA256_HASH_LEN);
	}
	
	
	static Sha256Hash getHmac(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen) {
		assert((key != nullptr || keyLen == 0) && (msg != nullptr || msgLen == 0));
		
		// Preprocess key
		uint8_t tempKey[SHA256_BLOCK_LEN] = {};
		if (keyLen <= SHA256_BLOCK_LEN)
			memcpy(tempKey, key, keyLen);
		else {
			Sha256Hash keyHash(getHash(key, keyLen));
			memcpy(tempKey, keyHash.data(), SHA256_HASH_LEN);
		}
		
		// Compute inner hash
		for (int i = 0; i < SHA256_BLOCK_LEN; i++)
			tempKey[i] ^= 0x36;
		uint32_t state[8];
		memcpy(state, INITIAL_STATE, sizeof(state));
		compress(state, tempKey, SHA256_BLOCK_LEN);
		Sha256Hash innerHash(getHash(msg, msgLen, state, SHA256_BLOCK_LEN));
		
		// Compute outer hash
		for (int i = 0; i < SHA256_BLOCK_LEN; i++)
			tempKey[i] ^= 0x36 ^ 0x5C;
		memcpy(state, INITIAL_STATE, sizeof(state));
		compress(state, tempKey, SHA256_BLOCK_LEN);
		return getHash(innerHash.data(), SHA256_HASH_LEN, state, SHA256_BLOCK_LEN);
	}
	
	
private:
	static Sha256Hash getHash(const uint8_t *msg, size_t len, const uint32_t initState[8], size_t prefixLen) {
		// Compress whole message blocks
		uint32_t state[8];
		memcpy(state, initState, sizeof(state));
		size_t off = len & ~static_cast<size_t>(SHA256_BLOCK_LEN - 1);
		compress(state, msg, off);
		
		// Final blocks, padding, and length
		uint8_t block[SHA256_BLOCK_LEN] = {};
		memcpy(block, &msg[off], len - off);
		off = len & (SHA256_BLOCK_LEN - 1);
		block[off] = 0x80;
		off++;
		if (off + 8 > SHA256_BLOCK_LEN) {
			compress(state, block, SHA256_BLOCK_LEN);
			memset(block, 0, SHA256_BLOCK_LEN);
		}
		uint64_t length = static_cast<uint64_t>(len + prefixLen) << 3;
		for (int i = 0; i < 8; i++)
			block[SHA256_BLOCK_LEN - 1 - i] = static_cast<uint8_t>(length >> (i << 3));
		compress(state, block, SHA256_BLOCK_LEN);
		
		// Uint32 array to bytes in big endian
		uint8_t result[SHA256_HASH_LEN];
		for (int i = 0; i < SHA256_HASH_LEN; i++)
			result[i] = static_cast<uint8_t>(state[i >> 2] >> ((3 - (i & 3)) << 3));
		return Sha256Hash(result, SHA256_HASH_LEN);
	}
	
	
public:
	static void compress(uint32_t state[8], const uint8_t *blocks, size_t len) {
		assert(state != nullptr && (blocks != nullptr || len == 0));
		assert(len % SHA256_BLOCK_LEN == 0);
		#define ROTR32(x, i)  (((x) << (32 - (i))) | ((x) >> (i)))
		uint32_t schedule[64];
		for (size_t i = 0; i < len; ) {
			
			// Message schedule
			for (int j = 0; j < 16; j++, i += 4) {
				schedule[j] =
					  static_cast<uint32_t>(blocks[i + 0]) << 24
					| static_cast<uint32_t>(blocks[i + 1]) << 16
					| static_cast<uint32_t>(blocks[i + 2]) <<  8
					| static_cast<uint32_t>(blocks[i + 3]) <<  0;
			}
			
			for (int j = 16; j < 64; j++) {
				schedule[j] = schedule[j - 16] + schedule[j - 7]
					+ (ROTR32(schedule[j - 15],  7) ^ ROTR32(schedule[j - 15], 18) ^ (schedule[j - 15] >>  3))
					+ (ROTR32(schedule[j -  2], 17) ^ ROTR32(schedule[j -  2], 19) ^ (schedule[j -  2] >> 10));
			}
			
			// The 64 rounds
			uint32_t a = state[0];
			uint32_t b = state[1];
			uint32_t c = state[2];
			uint32_t d = state[3];
			uint32_t e = state[4];
			uint32_t f = state[5];
			uint32_t g = state[6];
			uint32_t h = state[7];
			for (int j = 0; j < 64; j++) {
				uint32_t t1 = h + (ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25)) + (g ^ (e & (f ^ g))) + ROUND_CONSTANTS[j] + schedule[j];
				uint32_t t2 = (ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22)) + ((a & (b | c)) | (b & c));
				h = g;
				g = f;
				f = e;
				e = d + t1;
				d = c;
				c = b;
				b = a;
				a = t1 + t2;
			}
			state[0] += a;
			state[1] += b;
			state[2] += c;
			state[3] += d;
			state[4] += e;
			state[5] += f;
			state[6] += g;
			state[7] += h;
		}
		#undef ROT32
	}
	
	
	
	/* Stateful hasher fields and methods */
	
private:
	uint32_t state[8];
	uint64_t length;
	uint8_t buffer[SHA256_BLOCK_LEN];
	int bufferLen;
	
	
public:
	// Constructs a new SHA-256 hasher with an initially blank message.
	Sha256() :
			length(0),
			buffer(),
			bufferLen(0) {
		memcpy(state, INITIAL_STATE, sizeof(state));
	}
	
	
	// Appends message bytes to this ongoing hasher.
	void append(const uint8_t *bytes, int len) {
		assert(bytes != nullptr || len == 0);
		for (int i = 0; i < len; i++) {
			buffer[bufferLen] = bytes[i];
			bufferLen++;
			if (bufferLen == SHA256_BLOCK_LEN) {
				compress(state, buffer, SHA256_BLOCK_LEN);
				bufferLen = 0;
			}
		}
		length += len;
	}
	
	
	// Returns the SHA-256 hash of all the bytes seen. Destroys the state so that no further append() or getHash() will be valid.
	Sha256Hash getHash() {
		uint64_t bitLength = length << 3;
		uint8_t temp = 0x80;
		append(&temp, 1);
		temp = 0x00;
		while (bufferLen != 56)
			append(&temp, 1);
		for (int i = 0; i < 8; i++) {
			temp = static_cast<uint8_t>(bitLength >> ((7 - i) << 3));
			append(&temp, 1);
		}
		uint8_t result[SHA256_HASH_LEN];
		for (int i = 0; i < SHA256_HASH_LEN; i++)
			result[i] = static_cast<uint8_t>(state[i >> 2] >> ((3 - (i & 3)) << 3));
		return Sha256Hash(result, SHA256_HASH_LEN);
	}
	
	
	
	/* Class constants */
	
public:
	static const uint32_t INITIAL_STATE[8];
private:
	static const uint32_t ROUND_CONSTANTS[64];
	
};

// Static initializers
const uint32_t Sha256::INITIAL_STATE[8] = {
	UINT32_C(0x6A09E667), UINT32_C(0xBB67AE85), UINT32_C(0x3C6EF372), UINT32_C(0xA54FF53A),
	UINT32_C(0x510E527F), UINT32_C(0x9B05688C), UINT32_C(0x1F83D9AB), UINT32_C(0x5BE0CD19),
};
const uint32_t Sha256::ROUND_CONSTANTS[64] = {
	UINT32_C(0x428A2F98), UINT32_C(0x71374491), UINT32_C(0xB5C0FBCF), UINT32_C(0xE9B5DBA5),
	UINT32_C(0x3956C25B), UINT32_C(0x59F111F1), UINT32_C(0x923F82A4), UINT32_C(0xAB1C5ED5),
	UINT32_C(0xD807AA98), UINT32_C(0x12835B01), UINT32_C(0x243185BE), UINT32_C(0x550C7DC3),
	UINT32_C(0x72BE5D74), UINT32_C(0x80DEB1FE), UINT32_C(0x9BDC06A7), UINT32_C(0xC19BF174),
	UINT32_C(0xE49B69C1), UINT32_C(0xEFBE4786), UINT32_C(0x0FC19DC6), UINT32_C(0x240CA1CC),
	UINT32_C(0x2DE92C6F), UINT32_C(0x4A7484AA), UINT32_C(0x5CB0A9DC), UINT32_C(0x76F988DA),
	UINT32_C(0x983E5152), UINT32_C(0xA831C66D), UINT32_C(0xB00327C8), UINT32_C(0xBF597FC7),
	UINT32_C(0xC6E00BF3), UINT32_C(0xD5A79147), UINT32_C(0x06CA6351), UINT32_C(0x14292967),
	UINT32_C(0x27B70A85), UINT32_C(0x2E1B2138), UINT32_C(0x4D2C6DFC), UINT32_C(0x53380D13),
	UINT32_C(0x650A7354), UINT32_C(0x766A0ABB), UINT32_C(0x81C2C92E), UINT32_C(0x92722C85),
	UINT32_C(0xA2BFE8A1), UINT32_C(0xA81A664B), UINT32_C(0xC24B8B70), UINT32_C(0xC76C51A3),
	UINT32_C(0xD192E819), UINT32_C(0xD6990624), UINT32_C(0xF40E3585), UINT32_C(0x106AA070),
	UINT32_C(0x19A4C116), UINT32_C(0x1E376C08), UINT32_C(0x2748774C), UINT32_C(0x34B0BCB5),
	UINT32_C(0x391C0CB3), UINT32_C(0x4ED8AA4A), UINT32_C(0x5B9CCA4F), UINT32_C(0x682E6FF3),
	UINT32_C(0x748F82EE), UINT32_C(0x78A5636F), UINT32_C(0x84C87814), UINT32_C(0x8CC70208),
	UINT32_C(0x90BEFFFA), UINT32_C(0xA4506CEB), UINT32_C(0xBEF9A3F7), UINT32_C(0xC67178F2),
};
