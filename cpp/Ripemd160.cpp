/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include <cstring>
#include "Ripemd160.hpp"
#include "Utils.hpp"

using std::uint8_t;
using std::uint32_t;
using std::size_t;


void Ripemd160::getHash(const uint8_t msg[], size_t len, uint8_t hashResult[HASH_LEN]) {
	// Compress whole message blocks
	assert((msg != nullptr || len == 0) && hashResult != nullptr);
	uint32_t state[5] = {UINT32_C(0x67452301), UINT32_C(0xEFCDAB89), UINT32_C(0x98BADCFE), UINT32_C(0x10325476), UINT32_C(0xC3D2E1F0)};
	size_t off = len & ~static_cast<size_t>(BLOCK_LEN - 1);
	compress(state, msg, off);
	
	// Final blocks, padding, and length
	uint8_t block[BLOCK_LEN] = {};
	Utils::copyBytes(block, &msg[off], len - off);
	off = len & (BLOCK_LEN - 1);
	block[off] = 0x80;
	off++;
	if (off + 8 > BLOCK_LEN) {
		compress(state, block, BLOCK_LEN);
		std::memset(block, 0, BLOCK_LEN);
	}
	block[BLOCK_LEN - 8] = static_cast<uint8_t>((len & 0x1FU) << 3);
	len >>= 5;
	for (int i = 1; i < 8; i++, len >>= 8)
		block[BLOCK_LEN - 8 + i] = static_cast<uint8_t>(len);
	compress(state, block, BLOCK_LEN);
	
	// Uint32 array to bytes in little endian
	for (int i = 0; i < HASH_LEN; i++)
		hashResult[i] = static_cast<uint8_t>(state[i >> 2] >> ((i & 3) << 3));
}


void Ripemd160::compress(uint32_t state[5], const uint8_t blocks[], size_t len) {
	assert(len % BLOCK_LEN == 0);
	uint32_t schedule[16];
	for (size_t i = 0; i < len; ) {
		
		// Message schedule
		for (int j = 0; j < 16; j++, i += 4) {
			schedule[j] = static_cast<uint32_t>(blocks[i + 0]) <<  0
			            | static_cast<uint32_t>(blocks[i + 1]) <<  8
			            | static_cast<uint32_t>(blocks[i + 2]) << 16
			            | static_cast<uint32_t>(blocks[i + 3]) << 24;
		}
		
		// The 80 rounds
		uint32_t al = state[0], ar = state[0];
		uint32_t bl = state[1], br = state[1];
		uint32_t cl = state[2], cr = state[2];
		uint32_t dl = state[3], dr = state[3];
		uint32_t el = state[4], er = state[4];
		for (int j = 0; j < NUM_ROUNDS; j++) {
			uint32_t temp;
			temp = 0U + rotl32(0U + al + f(j, bl, cl, dl) + schedule[RL[j]] + KL[j >> 4], SL[j]) + el;
			al = el;
			el = dl;
			dl = rotl32(cl, 10);
			cl = bl;
			bl = temp;
			temp = 0U + rotl32(0U + ar + f(NUM_ROUNDS - 1 - j, br, cr, dr) + schedule[RR[j]] + KR[j >> 4], SR[j]) + er;
			ar = er;
			er = dr;
			dr = rotl32(cr, 10);
			cr = br;
			br = temp;
		}
		uint32_t temp = 0U + state[1] + cl + dr;
		state[1] = 0U + state[2] + dl + er;
		state[2] = 0U + state[3] + el + ar;
		state[3] = 0U + state[4] + al + br;
		state[4] = 0U + state[0] + bl + cr;
		state[0] = temp;
	}
}


uint32_t Ripemd160::f(int i, uint32_t x, uint32_t y, uint32_t z) {
	switch (i >> 4) {
		case 0:  return x ^ y ^ z;
		case 1:  return (x & y) | (~x & z);
		case 2:  return (x | ~y) ^ z;
		case 3:  return (x & z) | (y & ~z);
		case 4:  return x ^ (y | ~z);
		default:  assert(false);  return 0;  // Dummy value to please the compiler
	}
}


uint32_t Ripemd160::rotl32(uint32_t x, int i) {
	return ((0U + x) << i) | (x >> (32 - i));
}


// Static initializers
const uint32_t Ripemd160::KL[5] = {
	UINT32_C(0x00000000), UINT32_C(0x5A827999), UINT32_C(0x6ED9EBA1), UINT32_C(0x8F1BBCDC), UINT32_C(0xA953FD4E)};
const uint32_t Ripemd160::KR[5] = {
	UINT32_C(0x50A28BE6), UINT32_C(0x5C4DD124), UINT32_C(0x6D703EF3), UINT32_C(0x7A6D76E9), UINT32_C(0x00000000)};
const unsigned char Ripemd160::RL[NUM_ROUNDS] = {
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	 7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
	 3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
	 1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
	 4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13};
const unsigned char Ripemd160::RR[NUM_ROUNDS] = {
	 5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
	 6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
	15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
	 8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
	12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11};
const unsigned char Ripemd160::SL[NUM_ROUNDS] = {
	11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
	 7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
	11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
	11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
	 9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6};
const unsigned char Ripemd160::SR[NUM_ROUNDS] = {
	 8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
	 9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
	 9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
	15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
	 8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11};
