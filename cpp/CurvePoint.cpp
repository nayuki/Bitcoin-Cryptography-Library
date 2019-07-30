/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include "CountOps.hpp"
#include "CurvePoint.hpp"

using std::uint8_t;
using std::uint32_t;


CurvePoint::CurvePoint(const FieldInt &x_, const FieldInt &y_) :
	x(x_), y(y_), z(FI_ONE) {}


CurvePoint::CurvePoint(const char *xStr, const char *yStr) :
	x(xStr), y(yStr), z(FI_ONE) {}


CurvePoint::CurvePoint() :
	x(FI_ZERO), y(FI_ONE), z(FI_ZERO) {}


void CurvePoint::add(const CurvePoint &other) {
	countOps(functionOps);
	
	/* 
	 * (See https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates)
	 * Algorithm pseudocode:
	 * if (this == ZERO)
	 *   this = other
	 * else if (other == ZERO)
	 *   this = this
	 * else {
	 *   t0 = y0 * z1
	 *   t1 = y1 * z0
	 *   u0 = x0 * z1
	 *   u1 = x1 * z0
	 *   if (u0 == u1) {  // Same x coordinates
	 *     if (t0 == t1)  // Same y coordinates
	 *       this = twice()
	 *     else
	 *       this = ZERO
	 *   } else {
	 *     t = t0 - t1
	 *     u = u0 - u1
	 *     u2 = u^2
	 *     v = z0 * z1
	 *     w = t^2 * v - u2 * (u0 + u1)
	 *     x' = u * w
	 *     u3 = u2 * u
	 *     y' = t * (u0 * u2 - w) - t0 * u3
	 *     z' = u3 * v
	 *   }
	 * }
	 */
	bool thisZero  = this->isZero();
	bool otherZero = other.isZero();
	CurvePoint temp = *this;
	temp.twice();
	temp.replace(*this, static_cast<uint32_t>(otherZero));
	temp.replace(other, static_cast<uint32_t>(thisZero ));
	
	FieldInt u0 = this->x;
	FieldInt u1 = other.x;
	FieldInt t0 = this->y;
	FieldInt &t1 = x;  // Reuse memory
	t1 = other.y;
	u0.multiply(other.z);
	u1.multiply(this->z);
	t0.multiply(other.z);
	t1.multiply(this->z);
	bool sameX = u0 == u1;
	bool sameY = t0 == t1;
	temp.replace(ZERO, static_cast<uint32_t>(!thisZero & !otherZero & sameX & !sameY));
	
	FieldInt &t = y;  // Reuse memory
	t = t0;
	t.subtract(t1);
	FieldInt u = u0;
	u.subtract(u1);
	FieldInt u2 = u;
	u2.square();
	FieldInt &v = z;  // Reuse memory
	v.multiply(other.z);
	
	FieldInt w = t;
	w.square();
	w.multiply(v);
	u1.add(u0);
	u1.multiply(u2);
	w.subtract(u1);
	
	x = u;
	x.multiply(w);
	
	FieldInt &u3 = u1;  // Reuse memory
	u3 = u;
	u3.multiply(u2);
	
	u0.multiply(u2);
	u0.subtract(w);
	t.multiply(u0);
	t0.multiply(u3);
	t.subtract(t0);  // Assigns to y
	
	v.multiply(u3);  // Assigns to z
	
	this->replace(temp, static_cast<uint32_t>(thisZero | otherZero | sameX));
	countOps(8 * arithmeticOps);
	countOps(10 * fieldintCopyOps);
	countOps(1 * curvepointCopyOps);
}


void CurvePoint::twice() {
	countOps(functionOps);
	
	/* 
	 * (See https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates)
	 * Algorithm pseudocode:
	 * if (this == ZERO || y == 0)
	 *   this = ZERO
	 * else {
	 *   a = 0 (curve parameter)
	 *   t = 3 * x^2 + a * z^2
	 *   u = 2 * y * z
	 *   v = 2 * u * x * y
	 *   w = t^2 - 2 * v
	 *   x' = u * w
	 *   y' = t * (v - w) - 2 * (u * y)^2
	 *   z' = u^3
	 * }
	 */
	
	bool zeroResult = isZero() | (y == FI_ZERO);
	countOps(1 * arithmeticOps);
	
	FieldInt u = y;
	u.multiply(z);
	u.multiply2();
	
	FieldInt v = u;
	v.multiply(x);
	v.multiply(y);
	v.multiply2();
	
	x.square();
	FieldInt t = x;
	t.multiply2();
	t.add(x);
	
	FieldInt &w = z;  // Reuse memory
	w = t;
	w.square();
	x = v;
	x.multiply2();
	w.subtract(x);
	
	x = v;
	x.subtract(w);
	x.multiply(t);
	y.multiply(u);
	y.square();
	y.multiply2();
	x.subtract(y);
	y = x;
	
	x = u;
	x.multiply(w);
	
	z = u;
	z.square();
	z.multiply(u);
	
	this->replace(ZERO, static_cast<uint32_t>(zeroResult));
	countOps(10 * fieldintCopyOps);
}


void CurvePoint::multiply(const Uint256 &n) {
	// Precompute [this*0, this*1, ..., this*15]
	countOps(functionOps);
	constexpr int tableBits = 4;  // Do not modify
	constexpr unsigned int tableLen = 1U << tableBits;
	CurvePoint table[tableLen];  // Default-initialized with ZERO
	table[1] = *this;
	table[2] = *this;
	countOps(18 * curvepointCopyOps);
	table[2].twice();
	for (unsigned int i = 3; i < tableLen; i++) {
		countOps(loopBodyOps);
		table[i] = table[i - 1];
		table[i].add(*this);
		countOps(2 * arithmeticOps);
		countOps(1 * curvepointCopyOps);
	}
	
	// Process tableBits per iteration (windowed method)
	*this = ZERO;
	countOps(1 * curvepointCopyOps);
	for (int i = Uint256::NUM_WORDS * 32 - tableBits; i >= 0; i -= tableBits) {
		countOps(loopBodyOps);
		unsigned int inc = (n.value[i >> 5] >> (i & 31)) & (tableLen - 1);
		CurvePoint q = ZERO;  // Dummy initial value
		countOps(5 * arithmeticOps);
		countOps(1 * curvepointCopyOps);
		for (unsigned int j = 0; j < tableLen; j++) {
			countOps(loopBodyOps);
			q.replace(table[j], static_cast<uint32_t>(j == inc));
			countOps(1 * arithmeticOps);
		}
		this->add(q);
		if (i != 0) {
			for (int j = 0; j < tableBits; j++) {
				countOps(loopBodyOps);
				this->twice();
			}
		}
	}
}


void CurvePoint::normalize() {
	/* 
	 * Algorithm pseudocode:
	 * if (z != 0) {
	 *   x /= z
	 *   y /= z
	 *   z = 1
	 * } else {
	 *   x = x != 0 ? 1 : 0
	 *   y = y != 0 ? 1 : 0
	 *   z = 0
	 * }
	 */
	countOps(functionOps);
	CurvePoint norm = *this;
	norm.z.reciprocal();
	norm.x.multiply(norm.z);
	norm.y.multiply(norm.z);
	norm.z = FI_ONE;
	x.replace(FI_ONE, static_cast<uint32_t>(x != FI_ZERO));
	y.replace(FI_ONE, static_cast<uint32_t>(y != FI_ZERO));
	this->replace(norm, static_cast<uint32_t>(z != FI_ZERO));
	countOps(1 * fieldintCopyOps);
	countOps(1 * curvepointCopyOps);
}


void CurvePoint::replace(const CurvePoint &other, uint32_t enable) {
	assert((enable >> 1) == 0);
	countOps(functionOps);
	this->x.replace(other.x, enable);
	this->y.replace(other.y, enable);
	this->z.replace(other.z, enable);
}


bool CurvePoint::isOnCurve() const {
	countOps(functionOps);
	FieldInt left = y;
	left.square();
	FieldInt right = x;
	right.square();
	right.add(A);
	right.multiply(x);
	right.add(B);
	countOps(2 * arithmeticOps);
	countOps(2 * fieldintCopyOps);
	return (left == right) & !isZero();
}


bool CurvePoint::isZero() const {
	countOps(functionOps);
	countOps(2 * arithmeticOps);
	return (x == FI_ZERO) & (y != FI_ZERO) & (z == FI_ZERO);
}


bool CurvePoint::operator==(const CurvePoint &other) const {
	countOps(functionOps);
	countOps(2 * arithmeticOps);
	return (x == other.x) & (y == other.y) & (z == other.z);
}

bool CurvePoint::operator!=(const CurvePoint &other) const {
	countOps(functionOps);
	countOps(1 * arithmeticOps);
	return !(*this == other);
}


void CurvePoint::toCompressedPoint(uint8_t output[33]) const {
	assert(output != nullptr);
	output[0] = static_cast<uint8_t>((y.value[0] & 1) + 0x02);
	x.getBigEndianBytes(&output[1]);
}


CurvePoint CurvePoint::privateExponentToPublicPoint(const Uint256 &privExp) {
	assert((Uint256::ZERO < privExp) & (privExp < CurvePoint::ORDER));
	CurvePoint result = CurvePoint::G;
	result.multiply(privExp);
	result.normalize();
	return result;
}


// Static initializers
const FieldInt CurvePoint::FI_ZERO("0000000000000000000000000000000000000000000000000000000000000000");
const FieldInt CurvePoint::FI_ONE ("0000000000000000000000000000000000000000000000000000000000000001");
const FieldInt CurvePoint::A    ("0000000000000000000000000000000000000000000000000000000000000000");
const FieldInt CurvePoint::B    ("0000000000000000000000000000000000000000000000000000000000000007");
const Uint256  CurvePoint::ORDER("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const CurvePoint CurvePoint::G(
	FieldInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
	FieldInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
const CurvePoint CurvePoint::ZERO;  // Default constructor
