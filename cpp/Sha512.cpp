/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include "Sha512.hpp"
#include "Utils.hpp"

using std::uint8_t;
using std::uint64_t;
using std::size_t;


Sha512::Sha512() :
	length(0),
	bufferLen(0) {}


Sha512 &Sha512::append(const uint8_t bytes[], size_t len) {
	assert(bytes != nullptr || len == 0);
	for (size_t i = 0; i < len; i++) {
		buffer[bufferLen] = bytes[i];
		bufferLen++;
		if (bufferLen == BLOCK_LEN) {
			compress();
			bufferLen = 0;
		}
	}
	length += len;
	return *this;
}


void Sha512::getHash(uint8_t result[HASH_LEN]) {
	assert(result != nullptr);
	uint64_t bitLength = length << 3;
	uint8_t temp = 0x80;
	append(&temp, 1);
	temp = 0x00;
	while (bufferLen != 112)
		append(&temp, 1);
	for (int i = 0; i < 8; i++)
		append(&temp, 1);
	for (int i = 0; i < 8; i++) {
		temp = static_cast<uint8_t>(bitLength >> ((7 - i) << 3));
		append(&temp, 1);
	}
	for (int i = 0; i < HASH_LEN; i++)
		result[i] = static_cast<uint8_t>(state[i >> 3] >> ((7 - (i & 7)) << 3));
}


void Sha512::compress() {
	// Message schedule
	uint64_t schedule[NUM_ROUNDS] = {};
	for (int i = 0; i < 128; i++)
		schedule[i >> 3] |= static_cast<uint64_t>(buffer[i]) << ((7 - (i & 7)) << 3);
	
	for (int i = 16; i < NUM_ROUNDS; i++) {
		schedule[i] = 0U + schedule[i - 16] + schedule[i - 7]
			+ (rotr64(schedule[i - 15],  1) ^ rotr64(schedule[i - 15],  8) ^ (schedule[i - 15] >> 7))
			+ (rotr64(schedule[i -  2], 19) ^ rotr64(schedule[i -  2], 61) ^ (schedule[i -  2] >> 6));
	}
	
	// The 80 rounds
	uint64_t a = state[0];
	uint64_t b = state[1];
	uint64_t c = state[2];
	uint64_t d = state[3];
	uint64_t e = state[4];
	uint64_t f = state[5];
	uint64_t g = state[6];
	uint64_t h = state[7];
	for (int i = 0; i < NUM_ROUNDS; i++) {
		uint64_t t1 = 0U + h + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) + (g ^ (e & (f ^ g))) + ROUND_CONSTANTS[i] + schedule[i];
		uint64_t t2 = 0U + (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) + ((a & (b | c)) | (b & c));
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


void Sha512::getHash(const uint8_t msg[], size_t len, uint8_t hashResult[HASH_LEN]) {
	Sha512().append(msg, len).getHash(hashResult);
}


void Sha512::getHmac(const uint8_t key[], size_t keyLen, const uint8_t msg[], size_t msgLen, uint8_t result[HASH_LEN]) {
	assert(key != nullptr || keyLen == 0);
	
	// Preprocess key
	uint8_t tempKey[BLOCK_LEN] = {};
	if (keyLen <= BLOCK_LEN)
		Utils::copyBytes(tempKey, key, keyLen);
	else
		getHash(key, keyLen, tempKey);
	
	// Compute inner hash
	for (int i = 0; i < BLOCK_LEN; i++)
		tempKey[i] ^= 0x36;
	uint8_t innerHash[HASH_LEN] = {};
	Sha512()
		.append(tempKey, BLOCK_LEN)
		.append(msg, msgLen)
		.getHash(innerHash);
	
	// Compute outer hash
	for (int i = 0; i < BLOCK_LEN; i++)
		tempKey[i] ^= 0x36 ^ 0x5C;
	Sha512()
		.append(tempKey, BLOCK_LEN)
		.append(innerHash, HASH_LEN)
		.getHash(result);
}


uint64_t Sha512::rotr64(uint64_t x, int i) {
	return ((0U + x) << (64 - i)) | (x >> i);
}


const uint64_t Sha512::ROUND_CONSTANTS[NUM_ROUNDS] = {
	UINT64_C(0x428A2F98D728AE22), UINT64_C(0x7137449123EF65CD), UINT64_C(0xB5C0FBCFEC4D3B2F), UINT64_C(0xE9B5DBA58189DBBC),
	UINT64_C(0x3956C25BF348B538), UINT64_C(0x59F111F1B605D019), UINT64_C(0x923F82A4AF194F9B), UINT64_C(0xAB1C5ED5DA6D8118),
	UINT64_C(0xD807AA98A3030242), UINT64_C(0x12835B0145706FBE), UINT64_C(0x243185BE4EE4B28C), UINT64_C(0x550C7DC3D5FFB4E2),
	UINT64_C(0x72BE5D74F27B896F), UINT64_C(0x80DEB1FE3B1696B1), UINT64_C(0x9BDC06A725C71235), UINT64_C(0xC19BF174CF692694),
	UINT64_C(0xE49B69C19EF14AD2), UINT64_C(0xEFBE4786384F25E3), UINT64_C(0x0FC19DC68B8CD5B5), UINT64_C(0x240CA1CC77AC9C65),
	UINT64_C(0x2DE92C6F592B0275), UINT64_C(0x4A7484AA6EA6E483), UINT64_C(0x5CB0A9DCBD41FBD4), UINT64_C(0x76F988DA831153B5),
	UINT64_C(0x983E5152EE66DFAB), UINT64_C(0xA831C66D2DB43210), UINT64_C(0xB00327C898FB213F), UINT64_C(0xBF597FC7BEEF0EE4),
	UINT64_C(0xC6E00BF33DA88FC2), UINT64_C(0xD5A79147930AA725), UINT64_C(0x06CA6351E003826F), UINT64_C(0x142929670A0E6E70),
	UINT64_C(0x27B70A8546D22FFC), UINT64_C(0x2E1B21385C26C926), UINT64_C(0x4D2C6DFC5AC42AED), UINT64_C(0x53380D139D95B3DF),
	UINT64_C(0x650A73548BAF63DE), UINT64_C(0x766A0ABB3C77B2A8), UINT64_C(0x81C2C92E47EDAEE6), UINT64_C(0x92722C851482353B),
	UINT64_C(0xA2BFE8A14CF10364), UINT64_C(0xA81A664BBC423001), UINT64_C(0xC24B8B70D0F89791), UINT64_C(0xC76C51A30654BE30),
	UINT64_C(0xD192E819D6EF5218), UINT64_C(0xD69906245565A910), UINT64_C(0xF40E35855771202A), UINT64_C(0x106AA07032BBD1B8),
	UINT64_C(0x19A4C116B8D2D0C8), UINT64_C(0x1E376C085141AB53), UINT64_C(0x2748774CDF8EEB99), UINT64_C(0x34B0BCB5E19B48A8),
	UINT64_C(0x391C0CB3C5C95A63), UINT64_C(0x4ED8AA4AE3418ACB), UINT64_C(0x5B9CCA4F7763E373), UINT64_C(0x682E6FF3D6B2B8A3),
	UINT64_C(0x748F82EE5DEFB2FC), UINT64_C(0x78A5636F43172F60), UINT64_C(0x84C87814A1F0AB72), UINT64_C(0x8CC702081A6439EC),
	UINT64_C(0x90BEFFFA23631E28), UINT64_C(0xA4506CEBDE82BDE9), UINT64_C(0xBEF9A3F7B2C67915), UINT64_C(0xC67178F2E372532B),
	UINT64_C(0xCA273ECEEA26619C), UINT64_C(0xD186B8C721C0C207), UINT64_C(0xEADA7DD6CDE0EB1E), UINT64_C(0xF57D4F7FEE6ED178),
	UINT64_C(0x06F067AA72176FBA), UINT64_C(0x0A637DC5A2C898A6), UINT64_C(0x113F9804BEF90DAE), UINT64_C(0x1B710B35131C471B),
	UINT64_C(0x28DB77F523047D84), UINT64_C(0x32CAAB7B40C72493), UINT64_C(0x3C9EBE0A15C9BEBC), UINT64_C(0x431D67C49C100D4C),
	UINT64_C(0x4CC5D4BECB3E42B6), UINT64_C(0x597F299CFC657E2A), UINT64_C(0x5FCB6FAB3AD6FAEC), UINT64_C(0x6C44198C4A475817),
};
