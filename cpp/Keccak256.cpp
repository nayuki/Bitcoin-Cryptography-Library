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
	uint64_t a00 = state[ 0], a01 = state[ 1], a02 = state[ 2], a03 = state[ 3], a04 = state[ 4];
	uint64_t a05 = state[ 5], a06 = state[ 6], a07 = state[ 7], a08 = state[ 8], a09 = state[ 9];
	uint64_t a10 = state[10], a11 = state[11], a12 = state[12], a13 = state[13], a14 = state[14];
	uint64_t a15 = state[15], a16 = state[16], a17 = state[17], a18 = state[18], a19 = state[19];
	uint64_t a20 = state[20], a21 = state[21], a22 = state[22], a23 = state[23], a24 = state[24];
	
	for (int i = 0; i < NUM_ROUNDS; i++) {
		// Theta step
		uint64_t c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
		uint64_t c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
		uint64_t c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
		uint64_t c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
		uint64_t c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;
		uint64_t d0 = c4 ^ rotl64(c1, 1);
		uint64_t d1 = c0 ^ rotl64(c2, 1);
		uint64_t d2 = c1 ^ rotl64(c3, 1);
		uint64_t d3 = c2 ^ rotl64(c4, 1);
		uint64_t d4 = c3 ^ rotl64(c0, 1);
		a00 ^= d0;  a05 ^= d0;  a10 ^= d0;  a15 ^= d0;  a20 ^= d0;
		a01 ^= d1;  a06 ^= d1;  a11 ^= d1;  a16 ^= d1;  a21 ^= d1;
		a02 ^= d2;  a07 ^= d2;  a12 ^= d2;  a17 ^= d2;  a22 ^= d2;
		a03 ^= d3;  a08 ^= d3;  a13 ^= d3;  a18 ^= d3;  a23 ^= d3;
		a04 ^= d4;  a09 ^= d4;  a14 ^= d4;  a19 ^= d4;  a24 ^= d4;
		
		// Rho and pi steps
		uint64_t b00 = a00;
		uint64_t b16 = rotl64(a05, 36);
		uint64_t b07 = rotl64(a10,  3);
		uint64_t b23 = rotl64(a15, 41);
		uint64_t b14 = rotl64(a20, 18);
		uint64_t b10 = rotl64(a01,  1);
		uint64_t b01 = rotl64(a06, 44);
		uint64_t b17 = rotl64(a11, 10);
		uint64_t b08 = rotl64(a16, 45);
		uint64_t b24 = rotl64(a21,  2);
		uint64_t b20 = rotl64(a02, 62);
		uint64_t b11 = rotl64(a07,  6);
		uint64_t b02 = rotl64(a12, 43);
		uint64_t b18 = rotl64(a17, 15);
		uint64_t b09 = rotl64(a22, 61);
		uint64_t b05 = rotl64(a03, 28);
		uint64_t b21 = rotl64(a08, 55);
		uint64_t b12 = rotl64(a13, 25);
		uint64_t b03 = rotl64(a18, 21);
		uint64_t b19 = rotl64(a23, 56);
		uint64_t b15 = rotl64(a04, 27);
		uint64_t b06 = rotl64(a09, 20);
		uint64_t b22 = rotl64(a14, 39);
		uint64_t b13 = rotl64(a19,  8);
		uint64_t b04 = rotl64(a24, 14);
		
		// Chi step
		a00 = b00 ^ (~b01 & b02) ^ ROUND_CONSTANTS[i];  // Iota step
		a05 = b05 ^ (~b06 & b07);
		a10 = b10 ^ (~b11 & b12);
		a15 = b15 ^ (~b16 & b17);
		a20 = b20 ^ (~b21 & b22);
		a01 = b01 ^ (~b02 & b03);
		a06 = b06 ^ (~b07 & b08);
		a11 = b11 ^ (~b12 & b13);
		a16 = b16 ^ (~b17 & b18);
		a21 = b21 ^ (~b22 & b23);
		a02 = b02 ^ (~b03 & b04);
		a07 = b07 ^ (~b08 & b09);
		a12 = b12 ^ (~b13 & b14);
		a17 = b17 ^ (~b18 & b19);
		a22 = b22 ^ (~b23 & b24);
		a03 = b03 ^ (~b04 & b00);
		a08 = b08 ^ (~b09 & b05);
		a13 = b13 ^ (~b14 & b10);
		a18 = b18 ^ (~b19 & b15);
		a23 = b23 ^ (~b24 & b20);
		a04 = b04 ^ (~b00 & b01);
		a09 = b09 ^ (~b05 & b06);
		a14 = b14 ^ (~b10 & b11);
		a19 = b19 ^ (~b15 & b16);
		a24 = b24 ^ (~b20 & b21);
	}
	
	state[ 0] = a00;  state[ 1] = a01;  state[ 2] = a02;  state[ 3] = a03;  state[ 4] = a04;
	state[ 5] = a05;  state[ 6] = a06;  state[ 7] = a07;  state[ 8] = a08;  state[ 9] = a09;
	state[10] = a10;  state[11] = a11;  state[12] = a12;  state[13] = a13;  state[14] = a14;
	state[15] = a15;  state[16] = a16;  state[17] = a17;  state[18] = a18;  state[19] = a19;
	state[20] = a20;  state[21] = a21;  state[22] = a22;  state[23] = a23;  state[24] = a24;
}


uint64_t Keccak256::rotl64(uint64_t x, int i) {
	return ((0U + x) << i) | (x >> (64 - i));
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
