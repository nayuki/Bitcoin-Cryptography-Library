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
class Sha512 final {
	
	public: static constexpr int HASH_LEN = 64;
	private: static constexpr int BLOCK_LEN = 128;
	private: static constexpr int NUM_ROUNDS = 80;
	
	/*---- Static functions ----*/
	
	public: static void getHash(const std::uint8_t msg[], std::size_t len, std::uint8_t hashResult[HASH_LEN]);
	
	
	private: static void compress(std::uint64_t state[8], const std::uint8_t blocks[], std::size_t len);
	
	// Requires 1 <= i <= 63
	private: static std::uint64_t rotr64(std::uint64_t x, int i);
	
	private: Sha512();  // Not instantiable
	
	
	/*---- Class constants ----*/
	
	private: static const std::uint64_t ROUND_CONSTANTS[NUM_ROUNDS];
	
};
