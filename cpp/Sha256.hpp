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
#include "Sha256Hash.hpp"


/* 
 * Computes the SHA-256 hash of a sequence of bytes, returning a Sha256Hash object.
 * Provides three static methods, and an instantiable stateful hasher.
 */
#define SHA256_BLOCK_LEN 64
class Sha256 final {
	
	/* Static functions */
	
public:
	
	static Sha256Hash getHash(const uint8_t *msg, size_t len);
	
	
	static Sha256Hash getDoubleHash(const uint8_t *msg, size_t len);
	
	
	static Sha256Hash getHmac(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen);
	
	
private:
	static Sha256Hash getHash(const uint8_t *msg, size_t len, const uint32_t initState[8], size_t prefixLen);
	
	
public:
	static void compress(uint32_t state[8], const uint8_t *blocks, size_t len);
	
	
	
	/* Stateful hasher fields and methods */
	
private:
	uint32_t state[8];
	uint64_t length;
	uint8_t buffer[SHA256_BLOCK_LEN];
	int bufferLen;
	
	
public:
	// Constructs a new SHA-256 hasher with an initially blank message.
	Sha256();
	
	
	// Appends message bytes to this ongoing hasher.
	void append(const uint8_t *bytes, int len);
	
	
	// Returns the SHA-256 hash of all the bytes seen. Destroys the state so that no further append() or getHash() will be valid.
	Sha256Hash getHash();
	
	
	
	/* Class constants */
	
public:
	static const uint32_t INITIAL_STATE[8];
private:
	static const uint32_t ROUND_CONSTANTS[64];
	
};
