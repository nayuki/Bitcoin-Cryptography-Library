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
 * Provides two static methods, and an instantiable stateful hasher.
 */
class Sha512 final {
	
	/*---- Scalar constants ----*/
	
	public: static constexpr int HASH_LEN = 64;
	private: static constexpr int BLOCK_LEN = 128;
	private: static constexpr int NUM_ROUNDS = 80;
	
	
	
	/*---- Instance members ----*/
	
	private: std::uint64_t state[8] = {
		UINT64_C(0x6A09E667F3BCC908), UINT64_C(0xBB67AE8584CAA73B), UINT64_C(0x3C6EF372FE94F82B), UINT64_C(0xA54FF53A5F1D36F1),
		UINT64_C(0x510E527FADE682D1), UINT64_C(0x9B05688C2B3E6C1F), UINT64_C(0x1F83D9ABFB41BD6B), UINT64_C(0x5BE0CD19137E2179),
	};
	private: std::uint64_t length;
	private: std::uint8_t buffer[BLOCK_LEN];
	private: int bufferLen;
	
	
	// Constructs a new SHA-512 hasher with an initially blank message.
	public: explicit Sha512();
	
	
	// Appends message bytes to this ongoing hasher, and returns this object itself.
	public: Sha512 &append(const std::uint8_t bytes[], std::size_t len);
	
	
	// Returns the SHA-512 hash of all the bytes seen. Destroys the state so that no further append() or getHash() will be valid.
	public: void getHash(std::uint8_t result[HASH_LEN]);
	
	
	private: void compress();
	
	
	
	/*---- Static functions ----*/
	
	public: static void getHash(const std::uint8_t msg[], std::size_t len, std::uint8_t hashResult[HASH_LEN]);
	
	
	public: static void getHmac(const std::uint8_t key[], std::size_t keyLen, const std::uint8_t msg[], std::size_t msgLen, std::uint8_t result[HASH_LEN]);
	
	
	// Requires 1 <= i <= 63
	private: static std::uint64_t rotr64(std::uint64_t x, int i);
	
	
	
	/*---- Array constants ----*/
	
	private: static const std::uint64_t ROUND_CONSTANTS[NUM_ROUNDS];
	
};
