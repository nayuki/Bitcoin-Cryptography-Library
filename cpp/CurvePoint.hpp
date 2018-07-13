/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
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
	
	public: FieldInt x;
	public: FieldInt y;
	public: FieldInt z;  // The point is normalized iff (z = 1 OR (x,y,z)=(0,1,0))
	
	
	
	/*---- Constructors ----*/
	
	// Constructs a normalized point (z=1) from the given coordinates. Constant-time with respect to the values.
	public: explicit CurvePoint(const FieldInt &x_, const FieldInt &y_);
	
	
	// Constructs a normalized point (z=1) from the given string coordinates. Not constant-time.
	public: explicit CurvePoint(const char *xStr, const char *yStr);
	
	
	// Constructs the special "point at infinity" (normalized), which is used by ZERO and in multiply().
	private: CurvePoint();
	
	
	
	/*---- Arithmetic methods ----*/
	
	// Adds the given curve point to this point. The resulting state is
	// usually not normalized. Constant-time with respect to both values.
	public: void add(const CurvePoint &other);
	
	
	// Doubles this curve point. The resulting state is usually
	// not normalized. Constant-time with respect to this value.
	public: void twice();
	
	
	// Multiplies this point by the given unsigned integer. The resulting state
	// is usually not normalized. Constant-time with respect to both values.
	public: void multiply(const Uint256 &n);
	
	
	// Normalizes the coordinates of this point. Idempotent operation.
	// Constant-time with respect to this value.
	public: void normalize();
	
	
	// Copies the given point into this point if enable is 1, or does nothing if enable is 0.
	// Constant-time with respect to both values and the enable.
	public: void replace(const CurvePoint &other, std::uint32_t enable);
	
	
	// Tests whether this point is on the elliptic curve.
	// This point needs to be normalized before the method is called.
	// Zero is considered to be off the curve. Constant-time with respect to this value.
	public: bool isOnCurve() const;
	
	
	// Tests whether this point is equal to the special zero point.
	// This point need not be normalized. Constant-time with respect to this value.
	// This method is equivalent to, but more convenient than:
	// { CurvePoint temp(*this); temp.normalize(); return temp == ZERO; }
	public: bool isZero() const;
	
	
	// Tests whether this point equals the given point in all 3 coordinates. This comparison is
	// meaningful only if both points are normalized. Constant-time with respect to both values.
	public: bool operator==(const CurvePoint &other) const;
	
	// Tests whether this point mismatches the given point in any of the 3 coordinates. This comparison
	// is meaningful only if both points are normalized. Constant-time with respect to both values.
	public: bool operator!=(const CurvePoint &other) const;
	
	
	// Serializes this point in compressed format (header byte, x-coordinate in big-endian).
	// This point needs to be normalized before the method is called. Constant-time with respect to this value.
	public: void toCompressedPoint(std::uint8_t output[33]) const;
	
	
	/*---- Static functions ----*/
	
	// Returns a normalized public curve point for the given private exponent key.
	// Requires 0 < privExp < ORDER. Constant-time with respect to the value.
	public: static CurvePoint privateExponentToPublicPoint(const Uint256 &privExp);
	
	
	/*---- Class constants ----*/
	
	public: static const FieldInt FI_ZERO;  // These FieldInt constants are declared here because they are only needed in this class,
	public: static const FieldInt FI_ONE;   // and because of C++'s lack of guarantee of static initialization order.
	public: static const FieldInt A;       // Curve equation parameter
	public: static const FieldInt B;       // Curve equation parameter
	public: static const Uint256 ORDER;    // Order of base point, which is a prime number
	public: static const CurvePoint G;     // Base point (normalized)
	public: static const CurvePoint ZERO;  // Dummy point at infinity (normalized)
	
};
