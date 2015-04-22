/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>


/* 
 * An unsigned 256-bit integer, represented as eight 32-bits words in little endian.
 * All arithmetic operations are performed modulo 2^256 (standard unsigned overflow behavior).
 * Instances of this class are mutable.
 */
class Uint256 {
	
	#define NUM_WORDS 8
	#define MASK_ON UINT32_C(0xFFFFFFFF)
	
public:
	
	/* Fields */
	
	// The words representing this number in little endian, conceptually like this:
	// actualValue = value[0] << 0 | value[1] << 32 | ... | value[7] << 224.
	uint32_t value[NUM_WORDS];
	
	
	
	/* Constructors */
	
	// Constructs a Uint256 from the given 64-character hexadecimal string. Not constant-time.
	Uint256(const char *str) :
			value() {
		assert(strlen(str) == NUM_WORDS * 8);
		for (int i = 0; i < NUM_WORDS * 8; i++) {
			int chr = str[NUM_WORDS * 8 - 1 - i];
			int digit;
			if (chr >= '0' && chr <= '9')
				digit = chr - '0';
			else if (chr >= 'a' && chr <= 'f')
				digit = chr - 'a' + 10;
			else if (chr >= 'A' && chr <= 'F')
				digit = chr - 'A' + 10;
			else
				assert(false);
			value[i >> 3] |= digit << ((i & 7) << 2);
		}
	}
	
	
	
	/* Arithmetic methods */
	
	// Add the given number into this number, modulo 2^256. Constant-time with respect to both values.
	void add(const Uint256 &other) {
		add(other, MASK_ON);
	}
	
	
	// Adds the given number into this number, modulo 2^256. Mask must be 0x00000000 or 0xFFFFFFFF.
	// Returns the carry-out, which is 0 or 1. Constant-time with respect to both values.
	uint32_t add(const Uint256 &other, uint32_t mask) {
		assert(&other != this && (mask == 0 || mask == MASK_ON));
		uint32_t carry = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			uint64_t sum = static_cast<uint64_t>(value[i]) + (other.value[i] & mask) + carry;
			value[i] = static_cast<uint32_t>(sum);
			carry = static_cast<uint32_t>(sum >> 32);
		}
		return carry;
	}
	
	
	// Subtracts the given number from this number, modulo 2^256. Constant-time with respect to both values.
	void subtract(const Uint256 &other) {
		subtract(other, MASK_ON);
	}
	
	
	// Subtracts the given number from this number, modulo 2^256. Mask must be 0x00000000 or 0xFFFFFFFF.
	// Returns the borrow-out, which is 0 or 1. Constant-time with respect to both values.
	uint32_t subtract(const Uint256 &other, uint32_t mask) {
		assert(&other != this && (mask == 0 || mask == MASK_ON));
		uint32_t borrow = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			uint64_t diff = static_cast<uint64_t>(value[i]) - (other.value[i] & mask) - borrow;
			value[i] = static_cast<uint32_t>(diff);
			borrow = -static_cast<uint32_t>(diff >> 32);
		}
		return borrow;
	}
	
	
	// Shifts this number left by 1 bit (same as multiplying by 2), modulo 2^256.
	// Returns the old leftmost bit, which is 0 or 1. Constant-time with respect to this value.
	uint32_t shiftLeft1() {
		uint32_t prev = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			uint32_t cur = value[i];
			value[i] = cur << 1 | prev >> 31;
			prev = cur;
		}
		return prev >> 31;
	}
	
	
	// Shifts this number right by 1 bit (same as dividing by 2 and flooring).
	// Constant-time with respect to this value.
	void shiftRight1() {
		shiftRight1(MASK_ON);
	}
	
	
	// Shifts this number right by 1 bit (same as dividing by 2 and flooring).
	// Mask must be 0x00000000 or 0xFFFFFFFF. Constant-time with respect to this value.
	void shiftRight1(uint32_t mask) {
		assert(mask == 0 || mask == MASK_ON);
		uint32_t cur = value[0];
		for (int i = 0; i < NUM_WORDS - 1; i++) {
			uint32_t next = value[i + 1];
			value[i] = ((cur >> 1 | next << 31) & mask) | (cur & ~mask);
			cur = next;
		}
		value[NUM_WORDS - 1] = ((cur >> 1) & mask) | (cur & ~mask);
	}
	
	
	// Computes the multiplicative inverse of this number with respect to the given modulus.
	// If this number is zero, the reciprocal is zero. Constant-time with respect to this value.
	// The modulus must be odd and coprime to this number. This number must be less than the modulus.
	void reciprocal(const Uint256 &modulus) {
		// Extended binary GCD algorithm
		Uint256 x(modulus);  // Must be odd
		Uint256 y(*this);  // Odd or even, and must be less than x
		Uint256 a(ZERO);
		Uint256 b(ONE);
		Uint256 halfModulus(modulus);
		halfModulus.add(ONE);
		halfModulus.shiftRight1();
		// Loop invariant: x = a*this mod modulus, and y = b*this mod modulus
		for (int i = 0; i < NUM_WORDS * 32 * 2; i++) {
			// Try to reduce a trailing zero of y. Pseudocode:
			// if (y % 2 == 0) {
			//     y /= 2;
			//     b = b % 2 == 0 ? b / 2 : modulus - (modulus - b) / 2;
			// }
			uint32_t yEven = (y.value[0] & 1) - 1;
			uint32_t bOdd = -(b.value[0] & 1);
			y.shiftRight1(yEven);
			b.shiftRight1(yEven);
			b.add(halfModulus, yEven & bOdd);
			
			// If allowed, try to swap so that y >= x and then do y -= x. Pseudocode:
			// if (y % 2 != 0 && y != 1) {
			//     if (x > y) {
			//         x, y = y, x;
			//         a, b = b, a;
			//     }
			//     y -= x;
			//     b -= a;
			// }
			uint32_t enable = (-(y.value[0] & 1)) & (static_cast<uint32_t>(y == ONE) - 1);
			uint32_t swap = enable & (-static_cast<uint32_t>(x > y));
			x.swap(y, swap);
			y.subtract(x, enable);
			a.swap(b, swap);
			uint32_t borrow = b.subtract(a, enable);
			b.add(modulus, -borrow);
		}
		replace(b, -static_cast<uint32_t>(*this != ZERO));
	}
	
	
	/* Miscellaneous methods */
	
	// Copies the given value into this number if mask is 0xFFFFFFFF, or
	// does nothing if mask is 0x00000000. Constant-time with respect to both values.
	void replace(const Uint256 &other, uint32_t mask) {
		assert(mask == 0 || mask == MASK_ON);
		for (int i = 0; i < NUM_WORDS; i++)
			value[i] = (other.value[i] & mask) | (value[i] & ~mask);
	}
	
	
	// Swaps the value of this number with the given number if mask is 0xFFFFFFFF,
	// or does nothing if mask is 0x00000000. Constant-time with respect to both values.
	void swap(Uint256 &other, uint32_t mask) {
		assert(mask == 0 || mask == MASK_ON);
		for (int i = 0; i < NUM_WORDS; i++) {
			uint32_t x = this->value[i];
			uint32_t y = other.value[i];
			this->value[i] = (y & mask) | (x & ~mask);
			other.value[i] = (x & mask) | (y & ~mask);
		}
	}
	
	
	/* Equality/inequality operators */
	
	// Tests whether this value is equal to the given one. Constant-time with respect to both values.
	bool operator==(const Uint256 &other) const {
		uint32_t diff = 0;
		for (int i = 0; i < NUM_WORDS; i++)
			diff |= value[i] ^ other.value[i];
		return diff == 0;
	}
	
	bool operator!=(const Uint256 &other) const {
		return !(*this == other);
	}
	
	// Tests whether this value is less than the given one. Constant-time with respect to both values.
	bool operator<(const Uint256 &other) const {
		bool result = false;
		for (int i = 0; i < NUM_WORDS; i++) {
			bool eq = value[i] == other.value[i];
			result = (eq & result) | (!eq & (value[i] < other.value[i]));
		}
		return result;
	}
	
	bool operator<=(const Uint256 &other) const {
		return !(other < *this);
	}
	
	bool operator>(const Uint256 &other) const {
		return other < *this;
	}
	
	bool operator>=(const Uint256 &other) const {
		return !(*this < other);
	}
	
	
	#undef NUM_WORDS
	#undef MASK_ON
	
	
	
	/* Class constants */
	
public:
	static const Uint256 ZERO;
	static const Uint256 ONE;
	
};

// Static initializers
const Uint256 Uint256::ZERO("0000000000000000000000000000000000000000000000000000000000000000");
const Uint256 Uint256::ONE ("0000000000000000000000000000000000000000000000000000000000000001");
