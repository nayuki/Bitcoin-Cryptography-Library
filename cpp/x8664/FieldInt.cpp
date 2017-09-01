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
	uint32_t product0[NUM_WORDS * 2];
	asm_FieldInt_multiply256x256eq512(&product0[0], &this->value[0], &other.value[0]);
	
	// Barrett reduction algorithm begins here (see https://www.nayuki.io/page/barrett-reduction-algorithm).
	// Multiply by floor(2^512 / MODULUS), which is 2^256 + 2^32 + 0x3D1. Guaranteed to fit in a uint768.
	uint32_t product1[NUM_WORDS * 3];
	asm_FieldInt_multiplyBarrettStep0(product1, product0);
	
	// Virtually shift right by 512 bits, then multiply by MODULUS.
	// Note that MODULUS = 2^256 - 2^32 - 0x3D1. Result fits in a uint512.
	uint32_t product2[NUM_WORDS * 2];
	asm_FieldInt_multiplyBarrettStep1(product2, &product1[NUM_WORDS * 2]);
	
	// Compute product0 - product2, which fits in a uint257 (sic)
	uint32_t difference[NUM_WORDS + 1];
	asm_FieldInt_multiplyBarrettStep2(difference, product0, product2);
	
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
