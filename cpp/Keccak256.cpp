/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include "Keccak256.hpp"

using std::uint8_t;
using std::uint64_t;
using std::size_t;


void Keccak256::getHash(const uint8_t msg[], size_t len, uint8_t hashResult[HASH_LEN]) {
	assert((msg != nullptr || len == 0) && hashResult != nullptr);
	uint64_t state[25] = {};
	
	// XOR each message byte into the state, and absorb full blocks
	int blockOff = 0;
	for (size_t i = 0; i < len; i++) {
		state[blockOff >> 3] ^= static_cast<uint64_t>(msg[i]) << ((blockOff & 7) << 3);
		blockOff++;
		if (blockOff == BLOCK_SIZE) {
			absorb(state);
			blockOff = 0;
		}
	}
	
	// Final block and padding
	state[blockOff >> 3] ^= UINT64_C(0x01) << ((blockOff & 7) << 3);
	blockOff = BLOCK_SIZE - 1;
	state[blockOff >> 3] ^= UINT64_C(0x80) << ((blockOff & 7) << 3);
	absorb(state);
	
	// Uint64 array to bytes in little endian
	for (int i = 0; i < HASH_LEN; i++)
		hashResult[i] = static_cast<uint8_t>(state[i >> 3] >> ((i & 7) << 3));
}


void Keccak256::absorb(uint64_t state[25]) {
	uint64_t *a = state;
	for (int i = 0; i < NUM_ROUNDS; i++) {
		// Theta step
		uint64_t c[5] = {};
		for (int i = 0; i < 5; i++) {
			for (int j = 0; j < 25; j += 5)
				c[i] ^= a[i + j];
		}
		for (int i = 0; i < 5; i++) {
			uint64_t d = c[(i + 4) % 5] ^ rotl64(c[(i + 1) % 5], 1);
			for (int j = 0; j < 25; j += 5)
				a[i + j] ^= d;
		}
		
		// Rho and pi steps
		uint64_t b[25];
		for (int i = 0; i < 25; i++)
			b[i] = rotl64(a[PERMUTATION[i]], ROTATION[i]);
		
		// Chi step
		for (int i = 0; i < 5; i++) {
			for (int j = 0; j < 25; j += 5)
				a[i + j] = b[i + j] ^ (~b[(i + 1) % 5 + j] & b[(i + 2) % 5 + j]);
		}
		
		a[0] ^= ROUND_CONSTANTS[i];  // Iota step
	}
}


uint64_t Keccak256::rotl64(uint64_t x, int i) {
	return ((0U + x) << i) | (x >> ((64 - i) & 63));
}


// Static initializers
const uint64_t Keccak256::ROUND_CONSTANTS[NUM_ROUNDS] = {
	UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082), UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
	UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
	UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088), UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
	UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B), UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
	UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080), UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
	UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};
const unsigned char Keccak256::PERMUTATION[25] = {
	 0,  6, 12, 18, 24,
	 3,  9, 10, 16, 22,
	 1,  7, 13, 19, 20,
	 4,  5, 11, 17, 23,
	 2,  8, 14, 15, 21,
};
const unsigned char Keccak256::ROTATION[25] = {
	 0, 44, 43, 21, 14,
	28, 20,  3, 45, 61,
	 1,  6, 25,  8, 18,
	27, 36, 10, 15, 56,
	62, 55, 39, 41,  2,
};
