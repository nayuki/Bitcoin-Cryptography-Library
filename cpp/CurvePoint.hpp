/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
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
class CurvePoint {
	
	/* Fields */
	
public:
	FieldInt x;
	FieldInt y;
	FieldInt z;  // The point is normalized iff (z = 1 OR (x,y,z)=(0,1,0))
	
	
	
	/* Constructors */
	
public:
	// Constructs a normalized point (z=1) from the given coordinates. Constant-time with respect to the values.
	CurvePoint(const FieldInt &x_, const FieldInt &y_) :
		x(x_), y(y_), z(FieldInt::ONE) {}
	
	
	// Constructs a normalized point (z=1) from the given string coordinates. Not constant-time.
	CurvePoint(const char *xStr, const char *yStr) :
		x(xStr), y(yStr), z(FieldInt::ONE) {}
	
	
private:
	// Constructs the special "point at infinity" (normalized), which is used by ZERO and in multiply().
	CurvePoint() :
		x(FieldInt::ZERO), y(FieldInt::ONE), z(FieldInt::ZERO) {}
	
	
	
	/* Arithmetic methods */
public:
	
	// Adds the given curve point to this point. The resulting state is
	// usually not normalized. Constant-time with respect to both values.
	void add(const CurvePoint &other) {
		/* 
		 * (Derived from http://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates)
		 * if (this == ZERO)
		 *   this = other
		 * else if (other == ZERO)
		 *   this = this
		 * else {
		 *   u0 = x0 * z1
		 *   u1 = x1 * z0
		 *   v0 = y0 * z1
		 *   v1 = y1 * z0
		 *   if (v0 == v1)  // Same y coordinates
		 *     this = (u0 != u1) ? ZERO : twice()
		 *   else {
		 *     u = u0 - u1
		 *     v = v0 - v1
		 *     w = z0 * z1
		 *     t = w * v^2 - (u0 + u1) * u^2
		 *     x' = u * t
		 *     y' = v * (u0 * u^2 - t) - v0 * u^3
		 *     z' = u^3 * w
		 *   }
		 * }
		 */
		bool thisZero  = this->isZero();
		bool otherZero = other.isZero();
		this->replace(other, static_cast<uint32_t>(thisZero));
		
		FieldInt u0(this->x);
		FieldInt u1(other.x);
		FieldInt v0(this->y);
		FieldInt v1(other.y);
		u0.multiply(other.z);
		u1.multiply(this->z);
		v0.multiply(other.z);
		v1.multiply(this->z);
		
		bool sameX = u0 == u1;
		bool sameY = v0 == v1;
		CurvePoint twiced(*this);
		twiced.twice();
		
		FieldInt u(u0);
		u.subtract(u1);
		FieldInt v(v0);
		v.subtract(v1);
		FieldInt w(this->z);
		w.multiply(other.z);
		
		FieldInt u2(u);
		u2.square();
		FieldInt u3(u2);
		u3.multiply(u);
		
		u1.add(u0);
		u1.multiply(u2);
		FieldInt t(v);
		t.square();
		t.multiply(w);
		t.subtract(u1);
		
		uint32_t assign = -static_cast<uint32_t>(!thisZero & !otherZero & !sameY);
		u.multiply(t);
		this->x.replace(u, assign);
		w.multiply(u3);
		this->z.replace(w, assign);
		u0.multiply(u2);
		u0.subtract(t);
		u0.multiply(v);
		v0.multiply(u3);
		u0.subtract(v0);
		this->y.replace(u0, assign);
		
		bool cond = !thisZero & !otherZero & sameY;
		this->replace(ZERO  , static_cast<uint32_t>(cond & !sameX));
		this->replace(twiced, static_cast<uint32_t>(cond &  sameX));
	}
	
	
	// Doubles this curve point. The resulting state is usually
	// not normalized. Constant-time with respect to this value.
	void twice() {
		/* 
		 * (Derived from http://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates)
		 * if (this == ZERO || y == 0)
		 *   this = ZERO
		 * else {
		 *   a = 0 (curve parameter)
		 *   s = 2 * y * z
		 *   t = 2 * x * y * s
		 *   u = 3 * x^2 + a * z^2
		 *   v = u^2 - 2 * t
		 *   x' = s * v
		 *   y' = u * (t - v) - 2 * (y * s)^2
		 *   z' = s^3
		 * }
		 */
		bool zeroResult = isZero() | (y == FieldInt::ZERO);
		
		FieldInt s(z);
		s.multiply(y);
		s.multiply2();
		
		FieldInt t(s);
		t.multiply(y);
		t.multiply(x);
		t.multiply2();
		
		FieldInt t2(t);
		t2.multiply2();
		
		FieldInt u(x);
		u.square();
		u.multiply3();
		
		FieldInt v(u);
		v.square();
		v.subtract(t2);
		
		x = v;
		x.multiply(s);
		
		FieldInt s2(s);
		s2.square();
		
		z = s2;
		z.multiply(s);
		
		y.square();
		s2.multiply(y);
		s2.multiply2();
		t.subtract(v);
		u.multiply(t);
		u.subtract(s2);
		y = u;
		
		this->replace(ZERO, static_cast<uint32_t>(zeroResult));
	}
	
	
	// Multiplies this point by the given unsigned integer. The resulting state
	// is usually not normalized. Constant-time with respect to both values.
	void multiply(const Uint256 &n) {
		// Precompute [this*0, this*1, ..., this*15]
		CurvePoint table[16];  // Default-initialized with ZERO
		table[1] = *this;
		table[2] = *this;
		table[2].twice();
		for (int i = 3; i < 16; i++) {
			table[i] = table[i - 1];
			table[i].add(*this);
		}
		
		// Process 4 bits per iteration (windowed method)
		*this = ZERO;
		for (int i = 256 - 4; i >= 0; i -= 4) {
			if (i != 256 - 4) {
				for (int j = 0; j < 4; j++)
					this->twice();
			}
			unsigned int inc = (n.value[i >> 5] >> (i & 31)) & 15;
			CurvePoint q(ZERO);
			for (unsigned int j = 0; j < 16; j++)
				q.replace(table[j], static_cast<uint32_t>(j == inc));
			this->add(q);
		}
	}
	
	
	// Normalizes the coordinates of this point. If z != 0, then (x', y', z') = (x/z, y/z, 1);
	// otherwise special logic occurs. Constant-time with respect to this value.
	void normalize() {
		bool nonzero = z != FieldInt::ZERO;
		CurvePoint norm(*this);
		norm.z.reciprocal();
		norm.x.multiply(norm.z);
		norm.y.multiply(norm.z);
		norm.z = FieldInt::ONE;
		x.replace(FieldInt::ONE, -static_cast<uint32_t>(x != FieldInt::ZERO));
		y.replace(FieldInt::ONE, -static_cast<uint32_t>(y != FieldInt::ZERO));
		this->replace(norm, static_cast<uint32_t>(nonzero));
	}
	
	
	// Conditionally replaces this point's coordinates with the given point. Constant-time with respect to both values.
	void replace(const CurvePoint &other, uint32_t enable) {
		assert((enable >> 1) == 0);
		uint32_t mask = -enable;
		this->x.replace(other.x, mask);
		this->y.replace(other.y, mask);
		this->z.replace(other.z, mask);
	}
	
	
	// Tests whether this point is on the elliptic curve. This point needs to be normalized before the method is called.
	// Zero is considered to be off the curve. Constant-time with respect to this value.
	bool isOnCurve() const {
		FieldInt left(y);
		left.square();
		FieldInt right(x);
		right.square();
		right.add(A);
		right.multiply(x);
		right.add(B);
		return (left == right) & !isZero();
	}
	
	
	// Tests whether this point is equal to the special zero point. This point need not be normalized. Constant-time with respect to this value.
	// This method is equivalent to, but more convenient than: { CurvePoint temp(*this); temp.normalize(); return temp == ZERO; }
	bool isZero() const {
		return (x == FieldInt::ZERO) & (y != FieldInt::ZERO) & (z == FieldInt::ZERO);
	}
	
	
	// Tests whether this point equals the given point in all 3 coordinates. This comparison is
	// meaningful only if both points are normalized. Constant-time with respect to both values.
	bool operator==(const CurvePoint &other) const {
		return (x == other.x) & (y == other.y) & (z == other.z);
	}
	
	
	// Tests whether this point is unequal to the given point. Constant-time with respect to both values.
	bool operator!=(const CurvePoint &other) const {
		return !(*this == other);
	}
	
	
	// Serializes this point in compressed format. Constant-time with respect to this value.
	void toCompressedPoint(uint8_t output[33]) const {
		output[0] = (y.value[0] & 1) + 0x02;
		x.getBigEndianBytes(&output[1]);
	}
	
	
	/* Class constants */
	
public:
	static const FieldInt A;       // Curve equation parameter
	static const FieldInt B;       // Curve equation parameter
	static const Uint256 ORDER;    // Order of base point
	static const CurvePoint G;     // Base point (normalized)
	static const CurvePoint ZERO;  // Dummy point at infinity (normalized)
	
};

// Static initializers
const FieldInt CurvePoint::A    ("0000000000000000000000000000000000000000000000000000000000000000");
const FieldInt CurvePoint::B    ("0000000000000000000000000000000000000000000000000000000000000007");
const Uint256  CurvePoint::ORDER("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const CurvePoint CurvePoint::G(
	FieldInt("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
	FieldInt("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
const CurvePoint CurvePoint::ZERO;  // Special default constructor
