/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
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
	/* 
	 * (Derived from http://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates)
	 * Algorithm pseudocode:
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
	
	uint32_t assign = static_cast<uint32_t>(!thisZero & !otherZero & !sameY);
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


void CurvePoint::twice() {
	/* 
	 * (Derived from http://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates)
	 * Algorithm pseudocode:
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
	bool zeroResult = isZero() | (y == FI_ZERO);
	
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
	FieldInt v(u);
	u.multiply2();
	u.add(v);
	v = u;
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


void CurvePoint::multiply(const Uint256 &n) {
	// Precompute [this*0, this*1, ..., this*15]
	constexpr int tableBits = 4;  // Do not modify
	constexpr int tableLen = 1 << tableBits;
	CurvePoint table[tableLen];  // Default-initialized with ZERO
	table[1] = *this;
	table[2] = *this;
	table[2].twice();
	for (int i = 3; i < tableLen; i++) {
		table[i] = table[i - 1];
		table[i].add(*this);
	}
	
	// Process tableBits per iteration (windowed method)
	*this = ZERO;
	for (int i = Uint256::NUM_WORDS * 32 - tableBits; i >= 0; i -= tableBits) {
		unsigned int inc = (n.value[i >> 5] >> (i & 31)) & (tableLen - 1);
		CurvePoint q(ZERO);  // Dummy initial value
		for (unsigned int j = 0; j < tableLen; j++)
			q.replace(table[j], static_cast<uint32_t>(j == inc));
		this->add(q);
		if (i != 0) {
			for (int j = 0; j < tableBits; j++)
				this->twice();
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
	CurvePoint norm(*this);
	norm.z.reciprocal();
	norm.x.multiply(norm.z);
	norm.y.multiply(norm.z);
	norm.z = FI_ONE;
	x.replace(FI_ONE, static_cast<uint32_t>(x != FI_ZERO));
	y.replace(FI_ONE, static_cast<uint32_t>(y != FI_ZERO));
	this->replace(norm, static_cast<uint32_t>(z != FI_ZERO));
}


void CurvePoint::replace(const CurvePoint &other, uint32_t enable) {
	assert((enable >> 1) == 0);
	this->x.replace(other.x, enable);
	this->y.replace(other.y, enable);
	this->z.replace(other.z, enable);
}


bool CurvePoint::isOnCurve() const {
	FieldInt left(y);
	left.square();
	FieldInt right(x);
	right.square();
	right.add(A);
	right.multiply(x);
	right.add(B);
	return (left == right) & !isZero();
}


bool CurvePoint::isZero() const {
	return (x == FI_ZERO) & (y != FI_ZERO) & (z == FI_ZERO);
}


bool CurvePoint::operator==(const CurvePoint &other) const {
	return (x == other.x) & (y == other.y) & (z == other.z);
}

bool CurvePoint::operator!=(const CurvePoint &other) const {
	return !(*this == other);
}


void CurvePoint::toCompressedPoint(uint8_t output[33]) const {
	assert(output != nullptr);
	output[0] = (y.value[0] & 1) + 0x02;
	x.getBigEndianBytes(&output[1]);
}


CurvePoint CurvePoint::privateExponentToPublicPoint(const Uint256 &privExp) {
	assert((Uint256::ZERO < privExp) & (privExp < CurvePoint::ORDER));
	CurvePoint result(CurvePoint::G);
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
