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
	
	void asm_Uint256_replace(uint32_t dest[8], const uint32_t src[8], uint32_t enable);
	
	bool asm_Uint256_equalTo(const uint32_t left[8], const uint32_t right[8]);
	
	bool asm_Uint256_lessThan(const uint32_t left[8], const uint32_t right[8]);
	
}
