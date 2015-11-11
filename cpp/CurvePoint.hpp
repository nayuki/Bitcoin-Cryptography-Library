/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstdint>
#include "FieldInt.hpp"
#include "Uint256.hpp"


/*
 * A point on the secp256k1 elliptic curve for Bitcoin use, in projective coordinates.
 * Contains methods for computing point addition, doubling, and multiplication, and testing equality.
 * The ordinary affine coordinates of a point is (x/z, y/z). Instances of this class are mutable.
 * 
 * Points MUST be normalized before comparing for equality. Example of correct usage:
 *   CurvePoint a(...);
 *   CurvePoint b(...);
 *   CurvePoint c(...);
 *   
 *   a.add(b);
 *   a.multiply(50);
 *   
 *   a.normalize();
 *   c.normalize();
 *   if (a == c) { ... }
 */
class CurvePoint final {
	
	/*---- Fields ----*/
	
public:
	FieldInt x;
	FieldInt y;
	FieldInt z;  // The point is normalized iff (z = 1 OR (x,y,z)=(0,1,0))
	
	
	
	/*---- Constructors ----*/
public:
	
	// Constructs a normalized point (z=1) from the given coordinates. Constant-time with respect to the values.
	CurvePoint(const FieldInt &x_, const FieldInt &y_);
	
	
	// Constructs a normalized point (z=1) from the given string coordinates. Not constant-time.
	CurvePoint(const char *xStr, const char *yStr);
	
	
	// Constructs the special "point at infinity" (normalized), which is used by ZERO and in multiply().
private:
	CurvePoint();
	
	
	
	/*---- Arithmetic methods ----*/
public:
	
	// Adds the given curve point to this point. The resulting state is
	// usually not normalized. Constant-time with respect to both values.
	void add(const CurvePoint &other);
	
	
	// Doubles this curve point. The resulting state is usually
	// not normalized. Constant-time with respect to this value.
	void twice();
	
	
	// Multiplies this point by the given unsigned integer. The resulting state
	// is usually not normalized. Constant-time with respect to both values.
	void multiply(const Uint256 &n);
	
	
	// Normalizes the coordinates of this point. Idempotent operation.
	// Constant-time with respect to this value.
	void normalize();
	
	
	// Conditionally replaces this point's coordinates with the given point.
	// Constant-time with respect to both values and the enable.
	void replace(const CurvePoint &other, uint32_t enable);
	
	
	// Tests whether this point is on the elliptic curve.
	// This point needs to be normalized before the method is called.
	// Zero is considered to be off the curve. Constant-time with respect to this value.
	bool isOnCurve() const;
	
	
	// Tests whether this point is equal to the special zero point.
	// This point need not be normalized. Constant-time with respect to this value.
	// This method is equivalent to, but more convenient than:
	// { CurvePoint temp(*this); temp.normalize(); return temp == ZERO; }
	bool isZero() const;
	
	
	// Tests whether this point equals the given point in all 3 coordinates. This comparison is
	// meaningful only if both points are normalized. Constant-time with respect to both values.
	bool operator==(const CurvePoint &other) const;
	
	bool operator!=(const CurvePoint &other) const;
	
	
	// Serializes this point in compressed format (header byte, x-coordinate in big-endian).
	// Constant-time with respect to this value.
	void toCompressedPoint(uint8_t output[33]) const;
	
	
	/*---- Static functions ----*/
	
	// Returns a normalized public curve point for the given private exponent key.
	// Requires 0 < privExp < ORDER. Constant-time with respect to the value.
	static CurvePoint privateExponentToPublicPoint(const Uint256 &privExp);
	
	
	/*---- Class constants ----*/
	
public:
	static const FieldInt A;       // Curve equation parameter
	static const FieldInt B;       // Curve equation parameter
	static const Uint256 ORDER;    // Order of base point, which is a prime number
	static const CurvePoint G;     // Base point (normalized)
	static const CurvePoint ZERO;  // Dummy point at infinity (normalized)
	
};
