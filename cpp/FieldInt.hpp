/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

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
	
	public: using Uint256::NUM_WORDS;
	
	/*---- Fields ----*/
	
	public: using Uint256::value;
	
	
	
	/*---- Constructors ----*/
	
	// Constructs a FieldInt from the given 64-character hexadecimal string. Not constant-time.
	// If the syntax of the string is invalid, then an assertion will fail.
	public: explicit FieldInt(const char *str);
	
	
	// Constructs a FieldInt from the given Uint256, reducing it as necessary.
	// Constant-time with respect to the given value.
	public: explicit FieldInt(const Uint256 &val);
	
	
	
	/*---- Arithmetic methods ----*/
	
	// Adds the given number into this number, modulo the prime. Constant-time with respect to both values.
	public: void add(const FieldInt &other);
	
	
	// Subtracts the given number from this number, modulo the prime. Constant-time with respect to both values.
	public: void subtract(const FieldInt &other);
	
	
	// Doubles this number, modulo the prime. Constant-time with respect to this value.
	public: void multiply2();
	
	
	// Squares this number, modulo the prime. Constant-time with respect to this value.
	public: void square();
	
	
	// Multiplies the given number into this number, modulo the prime. Constant-time with respect to both values.
	public: void multiply(const FieldInt &other);
	
	
	// Computes the multiplicative inverse of this number with respect to the modulus.
	// If this number is zero, the reciprocal is zero. Constant-time with respect to this value.
	public: void reciprocal();
	
	
	/*---- Miscellaneous methods ----*/
	
	public: void replace(const FieldInt &other, std::uint32_t enable);
	
	public: using Uint256::getBigEndianBytes;
	
	
	/*---- Equality and inequality operators ----*/
	
	public: bool operator==(const FieldInt &other) const;
	
	public: bool operator!=(const FieldInt &other) const;
	
	public: bool operator<(const FieldInt &other) const;
	
	public: bool operator<=(const FieldInt &other) const;
	
	public: bool operator>(const FieldInt &other) const;
	
	public: bool operator>=(const FieldInt &other) const;
	
	
	private: bool operator<(const Uint256 &other) const;
	
	private: bool operator>=(const Uint256 &other) const;
	
	
	
	/*---- Class constants ----*/
	
	private: static const Uint256 MODULUS;  // Prime number
	
};
