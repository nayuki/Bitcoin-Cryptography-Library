/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstddef>
#include <cstdint>


/* 
 * Computes the RIPEMD-160 hash of a sequence of bytes. The hash value is 20 bytes long.
 * Provides just one static method.
 */
#define RIPEMD160_HASH_LEN 20
class Ripemd160 final {
	
	/*---- Static functions ----*/
	
public:
	static void getHash(const uint8_t *msg, size_t len, uint8_t hashResult[RIPEMD160_HASH_LEN]);
	
	
private:
	
	static void compress(uint32_t state[5], const uint8_t *blocks, size_t len);
	
	static uint32_t f(unsigned int i, uint32_t x, uint32_t y, uint32_t z);
	
	Ripemd160();  // Not instantiable
	
	
	
	/*---- Class constants ----*/
	
	static const uint32_t KL[5];       // Round constants for left line
	static const uint32_t KR[5];       // Round constants for right line
	static const unsigned int RL[80];  // Message schedule for left line
	static const unsigned int RR[80];  // Message schedule for right line
	static const unsigned int SL[80];  // Left-rotation for left line
	static const unsigned int SR[80];  // Left-rotation for right line
	
};
