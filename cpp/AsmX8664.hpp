/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstdint>

#ifndef USE_X8664_ASM_IMPL
	#define USE_X8664_ASM_IMPL 0
#endif


extern "C" {
	
	std::uint32_t asm_Uint256_add(std::uint32_t dest[8], const std::uint32_t src[8], std::uint32_t enable);
	
	std::uint32_t asm_Uint256_subtract(std::uint32_t dest[8], const std::uint32_t src[8], std::uint32_t enable);
	
	std::uint32_t asm_Uint256_shiftLeft1(std::uint32_t dest[8]);
	
	void asm_Uint256_shiftRight1(std::uint32_t dest[8], std::uint32_t enable);
	
	void asm_Uint256_replace(std::uint32_t dest[8], const std::uint32_t src[8], std::uint32_t enable);
	
	void asm_Uint256_swap(std::uint32_t left[8], std::uint32_t right[8], std::uint32_t enable);
	
	bool asm_Uint256_equalTo(const std::uint32_t left[8], const std::uint32_t right[8]);
	
	bool asm_Uint256_lessThan(const std::uint32_t left[8], const std::uint32_t right[8]);
	
	
	// Computes (uint512 z) = (uint256 x) * (uint256 y), correct for all input values.
	// (i.e. Input values are Uint256, not necessarily FieldInt.)
	void asm_FieldInt_multiply256x256eq512(std::uint32_t z[16], const std::uint32_t x[8], const std::uint32_t y[8]);
	
	// Computes (uint768 dest) = (uint512 src) * (2^256 + 2^32 + 0x3D1) % 2^768,
	// correct for all input values. If src < modulus^2, then the result does not overflow.
	void asm_FieldInt_multiplyBarrettStep0(std::uint32_t dest[24], const std::uint32_t src[16]);
	
	// Computes (uint512 dest) = (uint256 src) * (2^256 - 2^32 - 0x3D1), correct for all input values.
	void asm_FieldInt_multiplyBarrettStep1(std::uint32_t dest[16], const std::uint32_t src[8]);
	
	// Computes (uint288 z) = ((uint512 x) - (uint512 y)) % 2^288, correct for all input values.
	void asm_FieldInt_multiplyBarrettStep2(std::uint32_t z[9], const std::uint32_t x[16], const std::uint32_t y[16]);
	
}
