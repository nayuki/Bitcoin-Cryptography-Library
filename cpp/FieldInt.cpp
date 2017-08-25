/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include <cstring>
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
	uint32_t c = Uint256::add(other, 1);  // Perform addition
	assert((c >> 1) == 0);
	Uint256::subtract(MODULUS, c | static_cast<uint32_t>(*this >= MODULUS));  // Conditionally subtract modulus
}


void FieldInt::subtract(const FieldInt &other) {
	uint32_t b = Uint256::subtract(other, 1);  // Perform subtraction
	assert((b >> 1) == 0);
	Uint256::add(MODULUS, b);  // Conditionally add modulus
}


void FieldInt::multiply2() {
	uint32_t c = shiftLeft1();
	assert((c >> 1) == 0);
	Uint256::subtract(MODULUS, c | static_cast<uint32_t>(*this >= MODULUS));  // Conditionally subtract modulus
}


void FieldInt::square() {
	multiply(*this);
}


void FieldInt::multiply(const FieldInt &other) {
	// Compute raw product of (uint256 this->value) * (uint256 other.value) = (uint512 product0), via long multiplication
	uint32_t product0[NUM_WORDS * 2] = {};
	for (int i = 0; i < NUM_WORDS; i++) {
		uint32_t carry = 0;
		for (int j = 0; j < NUM_WORDS; j++) {
			uint64_t sum = static_cast<uint64_t>(this->value[i]) * other.value[j];
			sum += static_cast<uint64_t>(product0[i + j]) + carry;  // Does not overflow
			product0[i + j] = static_cast<uint32_t>(sum);
			carry = static_cast<uint32_t>(sum >> 32);
		}
		product0[i + NUM_WORDS] = carry;
	}
	
	// Barrett reduction algorithm begins here (see https://www.nayuki.io/page/barrett-reduction-algorithm).
	// Multiply by floor(2^512 / MODULUS), which is 2^256 + 2^32 + 0x3D1. Guaranteed to fit in a uint768.
	uint32_t product1[NUM_WORDS * 3];
	{
		uint32_t carry = 0;
		for (int i = 0; i < NUM_WORDS * 3; i++) {
			uint64_t sum = carry;
			if (i < NUM_WORDS * 2)
				sum += static_cast<uint64_t>(product0[i]) * 0x3D1;
			if (1 <= i && i < NUM_WORDS * 2 + 1)
				sum += product0[i - 1];
			if (i >= NUM_WORDS)
				sum += product0[i - NUM_WORDS];
			product1[i] = static_cast<uint32_t>(sum);
			carry = static_cast<uint32_t>(sum >> 32);
			assert(carry <= 0x3D3);
		}
		assert(carry == 0);
	}
	
	// Virtually shift right by 512 bits, then multiply by MODULUS.
	// Note that MODULUS = 2^256 - 2^32 - 0x3D1. Result fits in a uint512.
	uint32_t *product1Shifted = &product1[NUM_WORDS * 2];  // Length NUM_WORDS
	uint32_t product2[NUM_WORDS * 2];
	{
		uint32_t borrow = 0;
		for (int i = 0; i < NUM_WORDS * 2; i++) {
			uint64_t diff = -static_cast<uint64_t>(borrow);
			if (i < NUM_WORDS)
				diff -= static_cast<uint64_t>(product1Shifted[i]) * 0x3D1;
			if (1 <= i && i < NUM_WORDS + 1)
				diff -= product1Shifted[i - 1];
			if (i >= NUM_WORDS)
				diff += product1Shifted[i - NUM_WORDS];
			product2[i] = static_cast<uint32_t>(diff);
			borrow = -static_cast<uint32_t>(diff >> 32);
			assert(borrow <= 0x3D3);
		}
		assert(borrow == 0);
	}
	
	// Compute product0 - product2, which fits in a uint257 (sic)
	uint32_t difference[NUM_WORDS + 1];
	{
		uint32_t borrow = 0;
		for (int i = 0; i < NUM_WORDS + 1; i++) {
			uint64_t diff = static_cast<uint64_t>(product0[i]) - product2[i] - borrow;
			difference[i] = static_cast<uint32_t>(diff);
			borrow = -static_cast<uint32_t>(diff >> 32);
			assert((borrow >> 1) == 0);
		}
	}
	
	// Final conditional subtraction to yield a FieldInt value
	std::memcpy(this->value, difference, sizeof(value));
	uint32_t dosub = static_cast<uint32_t>((difference[NUM_WORDS] != 0) | (*this >= MODULUS));
	Uint256::subtract(MODULUS, dosub);
}


void FieldInt::reciprocal() {
	Uint256::reciprocal(MODULUS);
}


void FieldInt::replace(const FieldInt &other, uint32_t enable) {
	Uint256::replace(other, enable);
}


bool FieldInt::operator==(const FieldInt &other) const {
	return Uint256::operator==(other);
}

bool FieldInt::operator!=(const FieldInt &other) const {
	return Uint256::operator!=(other);
}

bool FieldInt::operator<(const FieldInt &other) const {
	return Uint256::operator<(other);
}

bool FieldInt::operator<=(const FieldInt &other) const {
	return Uint256::operator<=(other);
}

bool FieldInt::operator>(const FieldInt &other) const {
	return Uint256::operator>(other);
}

bool FieldInt::operator>=(const FieldInt &other) const {
	return Uint256::operator>=(other);
}


bool FieldInt::operator<(const Uint256 &other) const {
	return Uint256::operator<(other);
}

bool FieldInt::operator>=(const Uint256 &other) const {
	return Uint256::operator>=(other);
}


// Static initializers
const Uint256 FieldInt::MODULUS("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
