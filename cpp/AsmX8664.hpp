/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstdint>


extern "C" {
	
	uint32_t asm_Uint256_add(uint32_t dest[8], const uint32_t src[8], uint32_t enable);
	
	uint32_t asm_Uint256_subtract(uint32_t dest[8], const uint32_t src[8], uint32_t enable);
	
	uint32_t asm_Uint256_shiftLeft1(uint32_t dest[8]);
	
	void asm_Uint256_shiftRight1(uint32_t dest[8], uint32_t enable);
	
	void asm_Uint256_replace(uint32_t dest[8], const uint32_t src[8], uint32_t enable);
	
	void asm_Uint256_swap(uint32_t left[8], uint32_t right[8], uint32_t enable);
	
	bool asm_Uint256_equalTo(const uint32_t left[8], const uint32_t right[8]);
	
	bool asm_Uint256_lessThan(const uint32_t left[8], const uint32_t right[8]);
	
	void asm_FieldInt_multiply256x256eq512(uint32_t z[16], const uint32_t x[8], const uint32_t y[8]);
	
	void asm_FieldInt_multiplyBarrettStep0(uint32_t dest[24], const uint32_t src[16]);
	
	void asm_FieldInt_multiplyBarrettStep1(uint32_t dest[16], const uint32_t src[8]);
	
	void asm_FieldInt_multiplyBarrettStep2(uint32_t z[9], const uint32_t x[16], const uint32_t y[16]);
	
}
