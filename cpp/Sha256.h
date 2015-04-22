/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include "Sha256Hash.h"


/* 
 * Computes the SHA-256 hash of a sequence of bytes, returning a Sha256Hash object.
 * Provides three static methods.
 */
class Sha256 {
	
	#define BLOCK_LEN 64
	#define HASH_LEN 32
	
	/* Static functions */
	
public:
	
	static Sha256Hash getHash(const uint8_t *msg, size_t len) {
		return getHash(msg, len, INITIAL_STATE, 0);
	}
	
	
	static Sha256Hash getDoubleHash(const uint8_t *msg, size_t len) {
		Sha256Hash innerHash(getHash(msg, len));
		return getHash(innerHash.data(), HASH_LEN);
	}
	
	
	static Sha256Hash getHmac(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen) {
		// Preprocess key
		uint8_t tempKey[BLOCK_LEN] = {};
		if (keyLen <= BLOCK_LEN)
			memcpy(tempKey, key, keyLen);
		else {
			Sha256Hash keyHash(getHash(key, keyLen));
			memcpy(tempKey, keyHash.data(), HASH_LEN);
		}
		
		// Compute inner hash
		for (int i = 0; i < BLOCK_LEN; i++)
			tempKey[i] ^= 0x36;
		uint32_t state[8];
		memcpy(state, INITIAL_STATE, sizeof(state));
		compress(state, tempKey, BLOCK_LEN);
		Sha256Hash innerHash(getHash(msg, msgLen, state, BLOCK_LEN));
		
		// Compute outer hash
		for (int i = 0; i < BLOCK_LEN; i++)
			tempKey[i] ^= 0x36 ^ 0x5C;
		memcpy(state, INITIAL_STATE, sizeof(state));
		compress(state, tempKey, BLOCK_LEN);
		return getHash(innerHash.data(), HASH_LEN, state, BLOCK_LEN);
	}
	
	
private:
	
	static Sha256Hash getHash(const uint8_t *msg, size_t len, const uint32_t initState[8], size_t prefixLen) {
		// Compress whole message blocks
		uint32_t state[8];
		memcpy(state, initState, sizeof(state));
		size_t off = len & ~static_cast<size_t>(BLOCK_LEN - 1);
		compress(state, msg, off);
		
		// Final blocks, padding, and length
		uint8_t block[BLOCK_LEN] = {};
		memcpy(block, &msg[off], len - off);
		off = len & (BLOCK_LEN - 1);
		block[off] = 0x80;
		off++;
		if (off + 8 > BLOCK_LEN) {
			compress(state, block, BLOCK_LEN);
			memset(block, 0, BLOCK_LEN);
		}
		uint64_t length = static_cast<uint64_t>(len + prefixLen) << 3;
		for (int i = 0; i < 8; i++)
			block[BLOCK_LEN - 1 - i] = static_cast<uint8_t>(length >> (i << 3));
		compress(state, block, BLOCK_LEN);
		
		// Uint32 array to bytes in big endian
		uint8_t result[HASH_LEN];
		for (int i = 0; i < HASH_LEN; i++)
			result[i] = static_cast<uint8_t>(state[i >> 2] >> ((3 - (i & 3)) << 3));
		return Sha256Hash(result, HASH_LEN);
	}
	
	
	static void compress(uint32_t state[8], const uint8_t *blocks, size_t len) {
		#define ROTR32(x, i)  (((x) << (32 - (i))) | ((x) >> (i)))
		assert(len % BLOCK_LEN == 0);
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
	}
	
	
	Sha256() {}  // Not instantiable
	
	
	
	#undef BLOCK_LEN
	#undef HASH_LEN
	
	/* Class constants */
	
	static const uint32_t INITIAL_STATE[8];
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
