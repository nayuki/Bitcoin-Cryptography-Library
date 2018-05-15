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
#include "Sha256Hash.hpp"


/* 
 * Computes the SHA-256 hash of a sequence of bytes, returning a Sha256Hash object.
 * Provides three static methods, and an instantiable stateful hasher.
 */
class Sha256 final {
	
	public: static constexpr int BLOCK_LEN = 64;  // In bytes
	private: static constexpr int NUM_ROUNDS = 64;
	
	
	/*---- Static functions ----*/
	
	public: static Sha256Hash getHash(const std::uint8_t msg[], std::size_t len);
	
	
	public: static Sha256Hash getDoubleHash(const std::uint8_t msg[], std::size_t len);
	
	
	public: static Sha256Hash getHmac(const std::uint8_t key[], std::size_t keyLen, const std::uint8_t msg[], std::size_t msgLen);
	
	
	private: static Sha256Hash getHash(const std::uint8_t msg[], std::size_t len, const std::uint32_t initState[8], std::size_t prefixLen);
	
	
	public: static void compress(std::uint32_t state[8], const std::uint8_t blocks[], std::size_t len);
	
	// Requires 1 <= i <= 31
	private: static std::uint32_t rotr32(std::uint32_t x, int i);
	
	
	
	/*---- Stateful hasher fields and methods ----*/
	
	private: std::uint32_t state[8];
	private: std::uint64_t length;
	private: std::uint8_t buffer[BLOCK_LEN];
	private: int bufferLen;
	
	
	// Constructs a new SHA-256 hasher with an initially blank message.
	public: explicit Sha256();
	
	
	// Appends message bytes to this ongoing hasher.
	public: void append(const std::uint8_t bytes[], std::size_t len);
	
	
	// Returns the SHA-256 hash of all the bytes seen. Destroys the state so that no further append() or getHash() will be valid.
	public: Sha256Hash getHash();
	
	
	
	/*---- Class constants ----*/
	
	public: static const std::uint32_t INITIAL_STATE[8];
	private: static const std::uint32_t ROUND_CONSTANTS[NUM_ROUNDS];
	
};
