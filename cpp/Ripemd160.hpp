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
 * Computes the RIPEMD-160 hash of a sequence of bytes. The hash value is 20 bytes long.
 * Provides just one static method.
 */
class Ripemd160 final {
	
	public: static constexpr int HASH_LEN = 20;
	private: static constexpr int BLOCK_LEN = 64;
	private: static constexpr int NUM_ROUNDS = 80;
	
	/*---- Static functions ----*/
	
	public: static void getHash(const std::uint8_t msg[], std::size_t len, std::uint8_t hashResult[HASH_LEN]);
	
	
	private: static void compress(std::uint32_t state[5], const std::uint8_t blocks[], std::size_t len);
	
	private: static std::uint32_t f(int i, std::uint32_t x, std::uint32_t y, std::uint32_t z);
	
	// Requires 1 <= i <= 31
	private: static std::uint32_t rotl32(std::uint32_t x, int i);
	
	Ripemd160() = delete;  // Not instantiable
	
	
	
	/*---- Class constants ----*/
	
	private: static const std::uint32_t KL[5];       // Round constants for left line
	private: static const std::uint32_t KR[5];       // Round constants for right line
	private: static const unsigned char RL[NUM_ROUNDS];  // Message schedule for left line
	private: static const unsigned char RR[NUM_ROUNDS];  // Message schedule for right line
	private: static const unsigned char SL[NUM_ROUNDS];  // Left-rotation for left line
	private: static const unsigned char SR[NUM_ROUNDS];  // Left-rotation for right line
	
};
