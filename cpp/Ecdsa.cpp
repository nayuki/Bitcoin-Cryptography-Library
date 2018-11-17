/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include <cstdint>
#include <cstring>
#include "CountOps.hpp"
#include "Ecdsa.hpp"
#include "FieldInt.hpp"
#include "Sha256.hpp"

using std::uint8_t;
using std::uint32_t;


bool Ecdsa::sign(const Uint256 &privateKey, const Sha256Hash &msgHash, const Uint256 &nonce, Uint256 &outR, Uint256 &outS) {
	/* 
	 * Algorithm pseudocode:
	 * if (nonce outside range [1, order-1]) return false
	 * p = nonce * G
	 * r = p.x % order
	 * if (r == 0) return false
	 * s = nonce^-1 * (msgHash + r * privateKey) % order
	 * if (s == 0) return false
	 * s = min(s, order - s)
	 */
	countOps(functionOps);
	
	const Uint256 &order = CurvePoint::ORDER;
	const Uint256 &zero = Uint256::ZERO;
	if (nonce == zero || nonce >= order)
		return false;
	countOps(2 * arithmeticOps);
	
	const CurvePoint p = CurvePoint::privateExponentToPublicPoint(nonce);
	Uint256 r(p.x);
	r.subtract(order, static_cast<uint32_t>(r >= order));
	if (r == zero)
		return false;
	assert(r < order);
	countOps(1 * arithmeticOps);
	countOps(1 * uint256CopyOps);
	countOps(1 * curvepointCopyOps);
	
	Uint256 s = r;
	const Uint256 z(msgHash.value);
	multiplyModOrder(s, privateKey);
	uint32_t carry = s.add(z);
	s.subtract(order, carry | static_cast<uint32_t>(s >= order));
	countOps(1 * arithmeticOps);
	countOps(2 * uint256CopyOps);
	
	Uint256 kInv = nonce;
	kInv.reciprocal(order);
	multiplyModOrder(s, kInv);
	if (s == zero)
		return false;
	countOps(1 * arithmeticOps);
	countOps(1 * uint256CopyOps);
	
	Uint256 negS = order;
	negS.subtract(s);
	s.replace(negS, static_cast<uint32_t>(negS < s));  // To ensure low S values for BIP 62
	outR = r;
	outS = s;
	countOps(3 * uint256CopyOps);
	return true;
}


bool Ecdsa::signWithHmacNonce(const Uint256 &privateKey, const Sha256Hash &msgHash, Uint256 &outR, Uint256 &outS) {
	uint8_t privkeyBytes[Uint256::NUM_WORDS * 4];
	privateKey.getBigEndianBytes(privkeyBytes);
	const Sha256Hash hmac = Sha256::getHmac(privkeyBytes, sizeof(privkeyBytes), msgHash.value, Sha256Hash::HASH_LEN);
	const Uint256 nonce(hmac.value);
	return sign(privateKey, msgHash, nonce, outR, outS);
}


bool Ecdsa::verify(const CurvePoint &publicKey, const Sha256Hash &msgHash, const Uint256 &r, const Uint256 &s) {
	/* 
	 * Algorithm pseudocode:
	 * if (pubKey == zero || !(pubKey is normalized) ||
	 *     !(pubKey on curve) || n * pubKey != zero)
	 *   return false
	 * if (!(0 < r, s < order))
	 *   return false
	 * w = s^-1 % order
	 * u1 = (msgHash * w) % order
	 * u2 = (r * w) % order
	 * p = u1 * G + u2 * pubKey
	 * return r == p.x % order
	 */
	countOps(functionOps);
	countOps(11 * arithmeticOps);
	
	const Uint256 &order = CurvePoint::ORDER;
	const Uint256 &zero = Uint256::ZERO;
	CurvePoint q = publicKey;
	q.multiply(CurvePoint::ORDER);
	if (!(zero < r && r < order && zero < s && s < order))
		return false;
	countOps(5 * arithmeticOps);
	if (publicKey.isZero() || publicKey.z != CurvePoint::FI_ONE || !publicKey.isOnCurve() || !q.isZero())
		return false;
	countOps(4 * arithmeticOps);
	countOps(1 * curvepointCopyOps);
	
	Uint256 w = s;
	w.reciprocal(order);
	const Uint256 z(msgHash.value);
	Uint256 u1 = w;
	Uint256 u2 = w;
	multiplyModOrder(u1, z);
	multiplyModOrder(u2, r);
	countOps(4 * uint256CopyOps);
	
	CurvePoint p = CurvePoint::G;
	q = publicKey;
	p.multiply(u1);
	q.multiply(u2);
	p.add(q);
	p.normalize();
	countOps(2 * curvepointCopyOps);
	
	Uint256 px(p.x);
	px.subtract(order, static_cast<uint32_t>(px >= order));
	countOps(1 * uint256CopyOps);
	return r == px;
}


void Ecdsa::multiplyModOrder(Uint256 &x, const Uint256 &y) {
	/* 
	 * Russian peasant multiplication with modular reduction at each step. Algorithm pseudocode:
	 * z = 0
	 * for (i = 255 .. 0) {
	 *   z = (z * 2) % order
	 *   if (y.bit[i] == 1)
	 *     z = (z + x) % order
	 * }
	 * x = z
	 */
	countOps(functionOps);
	const Uint256 &mod = CurvePoint::ORDER;
	assert(&x != &y && x < mod);
	Uint256 z = Uint256::ZERO;
	countOps(1 * uint256CopyOps);
	
	for (int i = Uint256::NUM_WORDS * 32 - 1; i >= 0; i--) {
		countOps(loopBodyOps);
		// Multiply by 2
		uint32_t c = z.shiftLeft1();
		z.subtract(mod, c | static_cast<uint32_t>(z >= mod));
		// Conditionally add x
		uint32_t enable = (y.value[i >> 5] >> (i & 31)) & 1;
		c = z.add(x, enable);
		z.subtract(mod, c | static_cast<uint32_t>(z >= mod));
		assert(z < mod);
		countOps(7 * arithmeticOps);
	}
	x = z;
	countOps(1 * uint256CopyOps);
}
