/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include <cstring>
#include "AsmX8664.hpp"
#include "CountOps.hpp"
#include "FieldInt.hpp"

using std::uint32_t;
using std::uint64_t;


FieldInt::FieldInt(const char *str) :
		Uint256(str) {
	// C++ does not guarantee the order of initialization of static variables. If another class is
	// initializing a FieldInt constant, this class's modulus might not have been initialized yet.
	// Thus the assertion must be exempted in this situation. This logic relies on the fact that uninitialized
	// static variables are set to zero. Hence, only do the assertion if the modulus has been initialized already.
	if (MODULUS.value[0] != 0)
		assert(*this < MODULUS);
}


FieldInt::FieldInt(const Uint256 &val) :
		Uint256(val) {
	Uint256::subtract(MODULUS, static_cast<uint32_t>(*this >= MODULUS));
	assert(*this < MODULUS);
}


void FieldInt::add(const FieldInt &other) {
	countOps(functionOps);
	uint32_t c = Uint256::add(other);  // Perform addition
	assert((c >> 1) == 0);
	Uint256::subtract(MODULUS, c | static_cast<uint32_t>(*this >= MODULUS));  // Conditionally subtract modulus
	countOps(1 * arithmeticOps);
}


void FieldInt::subtract(const FieldInt &other) {
	countOps(functionOps);
	uint32_t b = Uint256::subtract(other);  // Perform subtraction
	assert((b >> 1) == 0);
	Uint256::add(MODULUS, b);  // Conditionally add modulus
}


void FieldInt::multiply2() {
	countOps(functionOps);
	uint32_t c = shiftLeft1();
	assert((c >> 1) == 0);
	Uint256::subtract(MODULUS, c | static_cast<uint32_t>(*this >= MODULUS));  // Conditionally subtract modulus
	countOps(1 * arithmeticOps);
}


void FieldInt::square() {
	countOps(functionOps);
	multiply(*this);
}


void FieldInt::multiply(const FieldInt &other) {
	countOps(functionOps);
	uint32_t difference[NUM_WORDS + 1];
	
	if (USE_X8664_ASM_IMPL) {
		// Compute raw product of (uint256 this->value) * (uint256 other.value) = (uint512 product0), via long multiplication
		uint32_t product0[NUM_WORDS * 2];
		asm_FieldInt_multiply256x256eq512(&product0[0], &this->value[0], &other.value[0]);
		countOps(105 * arithmeticOps);
		
		// Barrett reduction algorithm begins here (see https://www.nayuki.io/page/barrett-reduction-algorithm).
		// Multiply by floor(2^512 / MODULUS), which is 2^256 + 2^32 + 0x3D1. Guaranteed to fit in a uint768.
		uint32_t product1[NUM_WORDS * 3];
		asm_FieldInt_multiplyBarrettStep0(product1, product0);
		countOps((40 + 10*8 + 4) * arithmeticOps);
		
		// Virtually shift right by 512 bits, then multiply by MODULUS.
		// Note that MODULUS = 2^256 - 2^32 - 0x3D1. Result fits in a uint512.
		uint32_t product2[NUM_WORDS * 2];
		asm_FieldInt_multiplyBarrettStep1(product2, &product1[NUM_WORDS * 2]);
		countOps((29 + 12*4 + 5) * arithmeticOps);
		
		// Compute product0 - product2, which fits in a uint257 (sic)
		asm_FieldInt_multiplyBarrettStep2(difference, product0, product2);
		countOps(15 * arithmeticOps);
		
	} else {
		// Compute raw product of (uint256 this->value) * (uint256 other.value) = (uint512 product0), via long multiplication
		uint32_t product0[NUM_WORDS * 2] = {};
		countOps(NUM_WORDS * 2 * arithmeticOps);
		for (int i = 0; i < NUM_WORDS; i++) {
			countOps(loopBodyOps);
			uint32_t carry = 0;
			countOps(1 * arithmeticOps);
			for (int j = 0; j < NUM_WORDS; j++) {
				countOps(loopBodyOps);
				uint64_t sum = static_cast<uint64_t>(this->value[i]) * other.value[j];
				sum += static_cast<uint64_t>(product0[i + j]) + carry;  // Does not overflow
				product0[i + j] = static_cast<uint32_t>(sum);
				carry = static_cast<uint32_t>(sum >> 32);
				countOps(11 * arithmeticOps);
			}
			product0[i + NUM_WORDS] = carry;
			countOps(1 * arithmeticOps);
		}
		
		// Barrett reduction algorithm begins here (see https://www.nayuki.io/page/barrett-reduction-algorithm).
		// Multiply by floor(2^512 / MODULUS), which is 2^256 + 2^32 + 0x3D1. Guaranteed to fit in a uint768.
		uint32_t product1[NUM_WORDS * 3];
		{
			uint32_t carry = 0;
			countOps(1 * arithmeticOps);
			for (int i = 0; i < NUM_WORDS * 3; i++) {
				countOps(loopBodyOps);
				uint64_t sum = carry;
				countOps(2 * arithmeticOps);
				if (i < NUM_WORDS * 2) {
					sum += static_cast<uint64_t>(product0[i]) * 0x3D1;
					countOps(4 * arithmeticOps);
				}
				countOps(4 * arithmeticOps);
				if (1 <= i && i < NUM_WORDS * 2 + 1) {
					sum += product0[i - 1];
					countOps(3 * arithmeticOps);
				}
				countOps(2 * arithmeticOps);
				if (i >= NUM_WORDS) {
					sum += product0[i - NUM_WORDS];
					countOps(3 * arithmeticOps);
				}
				product1[i] = static_cast<uint32_t>(sum);
				carry = static_cast<uint32_t>(sum >> 32);
				assert(carry <= 0x3D3);
				countOps(2 * arithmeticOps);
			}
			assert(carry == 0);
		}
		
		// Virtually shift right by 512 bits, then multiply by MODULUS.
		// Note that MODULUS = 2^256 - 2^32 - 0x3D1. Result fits in a uint512.
		uint32_t *product1Shifted = &product1[NUM_WORDS * 2];  // Length NUM_WORDS
		uint32_t product2[NUM_WORDS * 2];
		countOps(1 * arithmeticOps);
		{
			uint32_t borrow = 0;
			countOps(1 * arithmeticOps);
			for (int i = 0; i < NUM_WORDS * 2; i++) {
				countOps(loopBodyOps);
				uint64_t diff = -static_cast<uint64_t>(borrow);
				countOps(1 * arithmeticOps);
				countOps(2 * arithmeticOps);
				if (i < NUM_WORDS) {
					diff -= static_cast<uint64_t>(product1Shifted[i]) * 0x3D1;
					countOps(4 * arithmeticOps);
				}
				countOps(4 * arithmeticOps);
				if (1 <= i && i < NUM_WORDS + 1) {
					diff -= product1Shifted[i - 1];
					countOps(3 * arithmeticOps);
				}
				countOps(2 * arithmeticOps);
				if (i >= NUM_WORDS) {
					diff += product1Shifted[i - NUM_WORDS];
					countOps(3 * arithmeticOps);
				}
				product2[i] = static_cast<uint32_t>(diff);
				borrow = -static_cast<uint32_t>(diff >> 32);
				assert(borrow <= 0x3D3);
				countOps(3 * arithmeticOps);
			}
			assert(borrow == 0);
		}
		
		// Compute product0 - product2, which fits in a uint257 (sic)
		{
			uint32_t borrow = 0;
			countOps(1 * arithmeticOps);
			for (int i = 0; i < NUM_WORDS + 1; i++) {
				countOps(loopBodyOps);
				uint64_t diff = static_cast<uint64_t>(product0[i]) - product2[i] - borrow;
				difference[i] = static_cast<uint32_t>(diff);
				borrow = -static_cast<uint32_t>(diff >> 32);
				assert((borrow >> 1) == 0);
				countOps(9 * arithmeticOps);
			}
		}
	}
	
	// Final conditional subtraction to yield a FieldInt value
	std::memcpy(this->value, difference, sizeof(value));
	countOps(functionOps);
	countOps(NUM_WORDS * arithmeticOps);
	uint32_t dosub = static_cast<uint32_t>((difference[NUM_WORDS] != 0) | (*this >= MODULUS));
	Uint256::subtract(MODULUS, dosub);
	countOps(2 * arithmeticOps);
}


void FieldInt::reciprocal() {
	countOps(functionOps);
	Uint256::reciprocal(MODULUS);
}


void FieldInt::replace(const FieldInt &other, uint32_t enable) {
	countOps(functionOps);
	Uint256::replace(other, enable);
}


bool FieldInt::operator==(const FieldInt &other) const {
	countOps(functionOps);
	return Uint256::operator==(other);
}

bool FieldInt::operator!=(const FieldInt &other) const {
	countOps(functionOps);
	return Uint256::operator!=(other);
}

bool FieldInt::operator<(const FieldInt &other) const {
	countOps(functionOps);
	return Uint256::operator<(other);
}

bool FieldInt::operator<=(const FieldInt &other) const {
	countOps(functionOps);
	return Uint256::operator<=(other);
}

bool FieldInt::operator>(const FieldInt &other) const {
	countOps(functionOps);
	return Uint256::operator>(other);
}

bool FieldInt::operator>=(const FieldInt &other) const {
	countOps(functionOps);
	return Uint256::operator>=(other);
}


bool FieldInt::operator<(const Uint256 &other) const {
	countOps(functionOps);
	return Uint256::operator<(other);
}

bool FieldInt::operator>=(const Uint256 &other) const {
	countOps(functionOps);
	return Uint256::operator>=(other);
}


// Static initializers
const Uint256 FieldInt::MODULUS("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
