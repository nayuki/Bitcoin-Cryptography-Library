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
	
public:
	static constexpr int HASH_LEN = 64;
	
	/*---- Static functions ----*/
	
	public: static void getHash(const std::uint8_t msg[], std::size_t len, std::uint8_t hashResult[HASH_LEN]);
	
	
	private: static void compress(std::uint64_t state[8], const std::uint8_t blocks[], std::size_t len);
	
	private: Sha512();  // Not instantiable
	
	
	/*---- Class constants ----*/
	
	private: static const std::uint64_t ROUND_CONSTANTS[80];
	
};
