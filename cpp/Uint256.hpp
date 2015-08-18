/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include "Utils.hpp"


/* 
 * An unsigned 256-bit integer, represented as eight unsigned 32-bit words in little endian.
 * All arithmetic operations are performed modulo 2^256 (the standard unsigned overflow behavior).
 * Instances of this class are mutable. All possible values are valid.
 * 
 * For example, the integer 0x0123456789abcdef000000001111111122222222333333334444444455555555 is represented by
 * the array {0x55555555, 0x44444444, 0x33333333, 0x22222222, 0x11111111, 0x00000000, 0x89abcdef, 0x01234567}.
 */
class Uint256 {
	
	#define NUM_WORDS 8
	
	/* Fields */
	
	// The words representing this number in little endian, conceptually like this:
	// actualValue = value[0] << 0 | value[1] << 32 | ... | value[7] << 224.
	// Remember, this field is public and mutable.
public:
	uint32_t value[NUM_WORDS];
	
	
	
	/* Constructors */
public:
	
	// Constructs a Uint256 initialized to zero. Constant-time.
	// For clarity, only use this constructor if the variable will be overwritten immediately
	// (pretend that this constructor leaves the value array uninitialized).
	// For actual zero values, please explicitly initialize them with: Uint256 num(Uint256::ZERO);
	Uint256() :
		value() {}
	
	
	// Constructs a Uint256 from the given 64-character hexadecimal string. Not constant-time.
	// If the syntax of the string is invalid, then an assertion will fail.
	explicit Uint256(const char *str) :
			value() {
		assert(str != nullptr && strlen(str) == NUM_WORDS * 8);
		for (int i = 0; i < NUM_WORDS * 8; i++) {
			int digit = Utils::parseHexDigit(str[NUM_WORDS * 8 - 1 - i]);
			assert(digit != -1);
			value[i >> 3] |= static_cast<uint32_t>(digit) << ((i & 7) << 2);
		}
	}
	
	
	// Constructs a Uint256 from the given 32 bytes encoded in big-endian.
	// Constant-time with respect to the input array values. All possible values are valid.
	explicit Uint256(const uint8_t b[NUM_WORDS * 4]) :
				value() {
		assert(b != nullptr);
		for (int i = 0; i < 32; i++)
			value[i >> 2] |= static_cast<uint32_t>(b[32 - 1 - i]) << ((i & 3) << 3);
	}
	
	
	
	/* Arithmetic methods */
	
	// Adds the given number into this number, modulo 2^256. 
	// The other number must be a distinct object. Constant-time with respect to both values.
	void add(const Uint256 &other) {
		add(other, 1);
	}
	
	
	// Adds the given number into this number, modulo 2^256. The other number must be a distinct object.
	// Enable must be 1 to perform the operation or 0 to do nothing. Returns the carry-out bit, which is 0 or 1.
	// Constant-time with respect to both values and the enable.
	uint32_t add(const Uint256 &other, uint32_t enable) {
		assert(&other != this && (enable >> 1) == 0);
		uint32_t mask = -enable;
		uint32_t carry = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			uint64_t sum = static_cast<uint64_t>(value[i]) + (other.value[i] & mask) + carry;
			value[i] = static_cast<uint32_t>(sum);
			carry = static_cast<uint32_t>(sum >> 32);
			assert((carry >> 1) == 0);
		}
		return carry;
	}
	
	
	// Subtracts the given number from this number, modulo 2^256.
	// The other number must be a distinct object. Constant-time with respect to both values.
	void subtract(const Uint256 &other) {
		subtract(other, 1);
	}
	
	
	// Subtracts the given number from this number, modulo 2^256. The other number must be a distinct object.
	// Enable must be 1 to perform the operation or 0 to do nothing. Returns the borrow-out bit, which is 0 or 1.
	// Constant-time with respect to both values and the enable.
	uint32_t subtract(const Uint256 &other, uint32_t enable) {
		assert(&other != this && (enable >> 1) == 0);
		uint32_t mask = -enable;
		uint32_t borrow = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			uint64_t diff = static_cast<uint64_t>(value[i]) - (other.value[i] & mask) - borrow;
			value[i] = static_cast<uint32_t>(diff);
			borrow = -static_cast<uint32_t>(diff >> 32);
			assert((borrow >> 1) == 0);
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
		shiftRight1(1);
	}
	
	
	// Shifts this number right by 1 bit (same as dividing by 2 and flooring).
	// Enable must be 1 to perform the operation or 0 to do nothing.
	// Constant-time with respect to this value and the enable.
	void shiftRight1(uint32_t enable) {
		assert((enable >> 1) == 0);
		uint32_t mask = -enable;
		uint32_t cur = value[0];
		for (int i = 0; i < NUM_WORDS - 1; i++) {
			uint32_t next = value[i + 1];
			value[i] = ((cur >> 1 | next << 31) & mask) | (cur & ~mask);
			cur = next;
		}
		value[NUM_WORDS - 1] = ((cur >> 1) & mask) | (cur & ~mask);
	}
	
	
	// Computes the multiplicative inverse of this number with respect to the given modulus.
	// The modulus must be odd and coprime to this number. This number must be less than the modulus.
	// If this number is zero, the reciprocal is zero. Constant-time with respect to this value.
	void reciprocal(const Uint256 &modulus) {
		// Extended binary GCD algorithm
		assert(&modulus != this);
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
			uint32_t yEven = (y.value[0] & 1) ^ 1;
			uint32_t bOdd = b.value[0] & 1;
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
			//     b %= modulus;
			// }
			uint32_t enable = (y.value[0] & 1) & (static_cast<uint32_t>(y == ONE) ^ 1);
			uint32_t doswap = enable & static_cast<uint32_t>(x > y);
			x.swap(y, doswap);
			y.subtract(x, enable);
			a.swap(b, doswap);
			uint32_t borrow = b.subtract(a, enable);
			b.add(modulus, borrow);
		}
		this->replace(b, static_cast<uint32_t>(*this != ZERO));
	}
	
	
	/* Miscellaneous methods */
	
	// Copies the given number into this number if enable is 1, or does nothing if enable is 0.
	// Constant-time with respect to both values and the enable.
	void replace(const Uint256 &other, uint32_t enable) {
		assert((enable >> 1) == 0);
		uint32_t mask = -enable;
		for (int i = 0; i < NUM_WORDS; i++)
			value[i] = (other.value[i] & mask) | (value[i] & ~mask);
	}
	
	
	// Swaps the value of this number with the given number if enable is 1, or does nothing if enable is 0.
	// Constant-time with respect to both values and the enable.
	void swap(Uint256 &other, uint32_t enable) {
		assert((enable >> 1) == 0);
		uint32_t mask = -enable;
		for (int i = 0; i < NUM_WORDS; i++) {
			uint32_t x = this->value[i];
			uint32_t y = other.value[i];
			this->value[i] = (y & mask) | (x & ~mask);
			other.value[i] = (x & mask) | (y & ~mask);
		}
	}
	
	
	// Writes this 256-bit integer as 32 bytes encoded in big endian to the given array.
	// Constant-time with respect to this value.
	void getBigEndianBytes(uint8_t b[NUM_WORDS * 4]) const {
		assert(b != nullptr);
		for (int i = 0; i < NUM_WORDS * 4; i++)
			b[NUM_WORDS * 4 - 1 - i] = static_cast<uint8_t>(value[i >> 2] >> ((i & 3) << 3));
	}
	
	
	/* Equality/inequality operators */
	
	// Tests whether this number is equal to the given number. Constant-time with respect to both values.
	bool operator==(const Uint256 &other) const {
		uint32_t diff = 0;
		for (int i = 0; i < NUM_WORDS; i++)
			diff |= value[i] ^ other.value[i];
		return diff == 0;
	}
	
	bool operator!=(const Uint256 &other) const {
		return !(*this == other);
	}
	
	
	// Tests whether this number is less than the given number. Constant-time with respect to both values.
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
	
	
	
	/* Class constants */
	
public:
	static const Uint256 ZERO;
	static const Uint256 ONE;
	
};

// Static initializers
const Uint256 Uint256::ZERO;
const Uint256 Uint256::ONE("0000000000000000000000000000000000000000000000000000000000000001");
