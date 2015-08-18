/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cassert>
#include <cstdint>
#include "Uint256.hpp"


/* 
 * An unsigned 256-bit integer modulo a specific prime number, for Bitcoin and secp256k1.
 * The input and output values of each method are always in the range [0, MODULUS).
 * 
 * Some behaviors are specific to FieldInt (such as reciprocal()), while others are
 * the same as Uint256 (such as comparisons). The number representation format is
 * the same as Uint256. It is illegal to set the value to be greater than or equal
 * to MODULUS; undefined behavior will result. Instances of this class are mutable.
 */
class FieldInt final : private Uint256 {
	
	#define NUM_WORDS 8
	
	/* Fields */
	
public:
	using Uint256::value;
	
	
	
	/* Constructors */
public:
	
	// Constructs a FieldInt from the given 64-character hexadecimal string. Not constant-time.
	// If the syntax of the string is invalid, then an assertion will fail.
	explicit FieldInt(const char *str) :
			Uint256(str) {
		assert(*this < MODULUS);
	}
	
	
	// Constructs a FieldInt from the given Uint256, reducing it as necessary.
	// Constant-time with respect to the given value.
	explicit FieldInt(const Uint256 &val) :
			Uint256(val) {
		Uint256::subtract(MODULUS, static_cast<uint32_t>(*this >= MODULUS));
	}
	
	
	
	/* Arithmetic methods */
public:
	
	// Adds the given number into this number, modulo the prime. Constant-time with respect to both values.
	void add(const FieldInt &other) {
		uint32_t c = Uint256::add(other, 1);  // Perform addition
		assert((c >> 1) == 0);
		Uint256::subtract(MODULUS, c | static_cast<uint32_t>(*this >= MODULUS));  // Conditionally subtract modulus
	}
	
	
	// Subtracts the given number from this number, modulo the prime. Constant-time with respect to both values.
	void subtract(const FieldInt &other) {
		uint32_t b = Uint256::subtract(other, 1);  // Perform subtraction
		assert((b >> 1) == 0);
		Uint256::add(MODULUS, b);  // Conditionally add modulus
	}
	
	
	// Doubles this number, modulo the prime. Constant-time with respect to this value.
	void multiply2() {
		uint32_t c = shiftLeft1();
		assert((c >> 1) == 0);
		Uint256::subtract(MODULUS, c | static_cast<uint32_t>(*this >= MODULUS));  // Conditionally subtract modulus
	}
	
	
	// Triples this number, modulo the prime. Constant-time with respect to this value.
	void multiply3() {
		const FieldInt copy(*this);
		multiply2();
		add(copy);
	}
	
	
	// Squares this number, modulo the prime. Constant-time with respect to this value.
	void square() {
		multiply(*this);
	}
	
	
	// Multiplies the given number into this number, modulo the prime. Constant-time with respect to both values.
	void multiply(const FieldInt &other) {
		// Compute raw product of this->value * other.value
		uint32_t product0[NUM_WORDS * 2];
		{
			uint64_t carry = 0;
			int i;
			for (i = 0; i < NUM_WORDS * 2 - 1; i++) {
				uint64_t sum = carry;
				uint32_t c = 0;
				if (i < NUM_WORDS) {
					for (int j = 0; j <= i; j++) {
						uint64_t prod = static_cast<uint64_t>(this->value[j]) * other.value[i - j];
						sum += prod;
						c += static_cast<uint32_t>(sum < prod);
					}
				} else {
					for (int j = NUM_WORDS - 1; j >= 0 && i - j < NUM_WORDS; j--) {
						uint64_t prod = static_cast<uint64_t>(this->value[i - j]) * other.value[j];
						sum += prod;
						c += static_cast<uint32_t>(sum < prod);
					}
				}
				assert(0 <= c && c <= NUM_WORDS);
				product0[i] = static_cast<uint32_t>(sum);
				carry = static_cast<uint64_t>(c) << 32 | sum >> 32;
			}
			product0[i] = static_cast<uint32_t>(carry);
			assert((carry >> 32) == 0);
		}
		
		// Barrett reduction algorithm begins here.
		// Multiply by floor(2^512 / MODULUS), which is 2^256 + 2^32 + 0x3D1
		uint32_t product1[NUM_WORDS * 3];
		{
			uint32_t carry = 0;
			for (int i = 0; i < NUM_WORDS * 3; i++) {
				uint64_t sum = carry;
				if (i < NUM_WORDS * 2)
					sum += static_cast<uint64_t>(product0[i]) * 0x3D1;
				if (i >= 1 && i < NUM_WORDS * 2 + 1)
					sum += product0[i - 1];
				if (i >= NUM_WORDS)
					sum += product0[i - NUM_WORDS];
				product1[i] = static_cast<uint32_t>(sum);
				carry = static_cast<uint32_t>(sum >> 32);
				assert(0 <= carry && carry <= 0x3D3);
			}
			assert(carry == 0);
		}
		
		// Virtually shift right by 512 bits, then multiply by MODULUS. Note that MODULUS = 2^256 - 2^32 - 0x3D1
		uint32_t *product1Shifted = &product1[NUM_WORDS * 2];  // Length NUM_WORDS
		uint32_t product2[NUM_WORDS * 2];
		{
			uint32_t borrow = 0;
			for (int i = 0; i < NUM_WORDS * 2; i++) {
				uint64_t diff = -static_cast<uint64_t>(borrow);
				if (i < NUM_WORDS)
					diff -= static_cast<uint64_t>(product1Shifted[i]) * 0x3D1;
				if (i >= 1 && i < NUM_WORDS + 1)
					diff -= product1Shifted[i - 1];
				if (i >= NUM_WORDS)
					diff += product1Shifted[i - NUM_WORDS];
				product2[i] = static_cast<uint32_t>(diff);
				borrow = -static_cast<uint32_t>(diff >> 32);
				assert(0 <= borrow && borrow <= 0x3D3);
			}
			assert(borrow == 0);
		}
		
		// Compute product0 - product2
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
		
		// Final conditional subtraction
		memcpy(this->value, difference, sizeof(value));
		uint32_t dosub = static_cast<uint32_t>((difference[NUM_WORDS] != 0) | (*this >= MODULUS));
		Uint256::subtract(MODULUS, dosub);
	}
	
	
	// Computes the multiplicative inverse of this number with respect to the modulus.
	// If this number is zero, the reciprocal is zero. Constant-time with respect to this value.
	void reciprocal() {
		Uint256::reciprocal(MODULUS);
	}
	
	
	/* Miscellaneous methods */
	
	void replace(const FieldInt &other, uint32_t enable) {
		Uint256::replace(other, enable);
	}
	
	using Uint256::getBigEndianBytes;
	
	
	/* Equality and inequality operators */
	
	bool operator==(const FieldInt &other) const {
		return Uint256::operator==(other);
	}
	
	bool operator!=(const FieldInt &other) const {
		return Uint256::operator!=(other);
	}
	
	bool operator<(const FieldInt &other) const {
		return Uint256::operator<(other);
	}
	
	bool operator<=(const FieldInt &other) const {
		return Uint256::operator<=(other);
	}
	
	bool operator>(const FieldInt &other) const {
		return Uint256::operator>(other);
	}
	
	bool operator>=(const FieldInt &other) const {
		return Uint256::operator>=(other);
	}
	
	
private:
	
	bool operator<(const Uint256 &other) const {
		return Uint256::operator<(other);
	}
	
	bool operator>=(const Uint256 &other) const {
		return Uint256::operator>=(other);
	}
	
	
	
	/* Class constants */
	
private:
	static const Uint256 MODULUS;  // Prime number
public:
	static const FieldInt ZERO;
	static const FieldInt ONE;
	
	#undef NUM_WORDS
	
};

// Static initializers
const Uint256  FieldInt::MODULUS("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
const FieldInt FieldInt::ZERO   ("0000000000000000000000000000000000000000000000000000000000000000");
const FieldInt FieldInt::ONE    ("0000000000000000000000000000000000000000000000000000000000000001");
