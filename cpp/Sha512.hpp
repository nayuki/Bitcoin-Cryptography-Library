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


/* 
 * Computes the SHA-512 hash of a sequence of bytes. The hash value is 64 bytes long.
 * Provides just one static method.
 */
#define SHA512_HASH_LEN 64
class Sha512 final {
	
	/*---- Static functions ----*/
	
public:
	static void getHash(const uint8_t *msg, size_t len, uint8_t hashResult[SHA512_HASH_LEN]);
	
	
private:
	
	static void compress(uint64_t state[8], const uint8_t *blocks, size_t len);
	
	Sha512();  // Not instantiable
	
	
	/*---- Class constants ----*/
	
	static const uint64_t ROUND_CONSTANTS[80];
	
};
