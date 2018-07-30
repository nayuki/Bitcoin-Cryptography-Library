/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include <cstring>
#include "Sha256.hpp"
#include "Utils.hpp"

using std::uint8_t;
using std::uint32_t;
using std::uint64_t;
using std::size_t;


Sha256::Sha256() :
	length(0),
	bufferLen(0) {}


Sha256 &Sha256::append(const uint8_t bytes[], size_t len) {
	assert(bytes != nullptr || len == 0);
	for (size_t i = 0; i < len; i++) {
		buffer[bufferLen] = bytes[i];
		bufferLen++;
		if (bufferLen == BLOCK_LEN) {
			compress(state, buffer);
			bufferLen = 0;
		}
	}
	length += len;
	return *this;
}


Sha256Hash Sha256::getHash() {
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
	uint8_t result[Sha256Hash::HASH_LEN];
	for (size_t i = 0; i < sizeof(state) / sizeof(state[0]); i++)
		Utils::storeBigUint32(state[i], &result[i * 4]);
	return Sha256Hash(result, Sha256Hash::HASH_LEN);
}


Sha256Hash Sha256::getHash(const uint8_t msg[], size_t len) {
	return Sha256().append(msg, len).getHash();
}


Sha256Hash Sha256::getDoubleHash(const uint8_t msg[], size_t len) {
	const Sha256Hash innerHash = getHash(msg, len);
	return getHash(innerHash.value, Sha256Hash::HASH_LEN);
}


Sha256Hash Sha256::getHmac(const uint8_t key[], size_t keyLen, const uint8_t msg[], size_t msgLen) {
	assert(key != nullptr || keyLen == 0);
	
	// Preprocess key
	uint8_t tempKey[BLOCK_LEN] = {};
	if (keyLen <= BLOCK_LEN)
		Utils::copyBytes(tempKey, key, keyLen);
	else {
		const Sha256Hash keyHash = getHash(key, keyLen);
		std::memcpy(tempKey, keyHash.value, Sha256Hash::HASH_LEN);
	}
	
	// Compute inner hash
	for (int i = 0; i < BLOCK_LEN; i++)
		tempKey[i] ^= 0x36;
	const Sha256Hash innerHash = Sha256()
		.append(tempKey, BLOCK_LEN)
		.append(msg, msgLen)
		.getHash();
	
	// Compute outer hash
	for (int i = 0; i < BLOCK_LEN; i++)
		tempKey[i] ^= 0x36 ^ 0x5C;
	return Sha256()
		.append(tempKey, BLOCK_LEN)
		.append(innerHash.value, Sha256Hash::HASH_LEN)
		.getHash();
}


void Sha256::compress(uint32_t state[8], const uint8_t block[BLOCK_LEN]) {
	assert(state != nullptr && block != nullptr);
	
	// Message schedule
	uint32_t schedule[NUM_ROUNDS] = {};
	for (int i = 0; i < 64; i++)
		schedule[i >> 2] |= static_cast<uint32_t>(block[i]) << ((3 - (i & 3)) << 3);
	
	for (int i = 16; i < NUM_ROUNDS; i++) {
		schedule[i] = 0U + schedule[i - 16] + schedule[i - 7]
			+ (rotr32(schedule[i - 15],  7) ^ rotr32(schedule[i - 15], 18) ^ (schedule[i - 15] >>  3))
			+ (rotr32(schedule[i -  2], 17) ^ rotr32(schedule[i -  2], 19) ^ (schedule[i -  2] >> 10));
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
	for (int i = 0; i < NUM_ROUNDS; i++) {
		uint32_t t1 = 0U + h + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + (g ^ (e & (f ^ g))) + ROUND_CONSTANTS[i] + schedule[i];
		uint32_t t2 = 0U + (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & (b | c)) | (b & c));
		h = g;
		g = f;
		f = e;
		e = 0U + d + t1;
		d = c;
		c = b;
		b = a;
		a = 0U + t1 + t2;
	}
	state[0] = 0U + state[0] + a;
	state[1] = 0U + state[1] + b;
	state[2] = 0U + state[2] + c;
	state[3] = 0U + state[3] + d;
	state[4] = 0U + state[4] + e;
	state[5] = 0U + state[5] + f;
	state[6] = 0U + state[6] + g;
	state[7] = 0U + state[7] + h;
}


uint32_t Sha256::rotr32(uint32_t x, int i) {
	return ((0U + x) << (32 - i)) | (x >> i);
}


const uint32_t Sha256::ROUND_CONSTANTS[NUM_ROUNDS] = {
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
