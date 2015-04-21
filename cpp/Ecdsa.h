/* 
 * Copyright (c) Project Nayuki
 * http://www.nayuki.io/
 */

#pragma once

#include <cassert>
#include <cstdint>
#include "CurvePoint.h"
#include "FieldInt.h"
#include "Sha256Hash.h"
#include "Uint256.h"


class Ecdsa {
	
public:
	// Note: The nonce must be unique, unpredictable, and secret.
	// Otherwise the ECDSA signature may leak the private key.
	// Returns true if signing was successful, false if a new nonce must be chosen.
	static bool sign(const Uint256 &privateKey, const Sha256Hash &msgHash, const Uint256 &nonce, Uint256 &outR, Uint256 &outS) {
		/* 
		 * Pseudocode:
		 * if (nonce outside [1, order-1]) return false;
		 * p = nonce * G;
		 * r = p.x % order;
		 * if (r == 0) return false;
		 * s = k^-1 * (msgHash + r * privateKey) % order;
		 * if (s == 0) return false;
		 */
		
		const Uint256 &n = CurvePoint::ORDER;
		const Uint256 &zero = Uint256::ZERO;
		if ((nonce == zero) | (nonce >= n))
			return false;
		
		CurvePoint p(CurvePoint::G);
		p.multiply(nonce);
		p.normalize();
		
		Uint256 r(zero);
		for (int i = 0; i < 8; i++)
			r.value[i] = p.x.value[i];
		r.subtract(n, -static_cast<uint32_t>(r >= n));
		if (r == zero)
			return false;
		assert(r < n);
		
		Uint256 s(r);
		multiplyModOrder(s, privateKey);
		
		Uint256 z(zero);
		for (int i = 0; i < 32; i++)
			z.value[i >> 2] |= static_cast<uint32_t>(msgHash.getByte(31 - i)) << ((i & 3) << 3);
		
		uint32_t carry = s.add(z, UINT32_C(0xFFFFFFFF));
		s.subtract(n, -(carry | static_cast<uint32_t>(s >= n)));
		
		Uint256 kInv(nonce);
		kInv.reciprocal(n);
		
		multiplyModOrder(s, kInv);
		if (s == zero)
			return false;
		
		outR = r;
		outS = s;
		return true;
	}
	
	
private:
	
	static void multiplyModOrder(Uint256 &x, const Uint256 &y) {
		// Russian peasant multiplication with modular reduction at each step
		assert(&x != &y && x < CurvePoint::ORDER);
		const Uint256 copy(x);
		memset(x.value, 0, sizeof(x.value));
		for (int i = 255; i >= 0; i--) {
			// Multiply by 2
			uint32_t c = x.shiftLeft1();
			x.subtract(CurvePoint::ORDER, -(c | static_cast<uint32_t>(x >= CurvePoint::ORDER)));
			// Conditionally add 'copy'
			uint32_t mask = -((y.value[i >> 5] >> (i & 31)) & 1);
			c = x.add(copy, mask);
			x.subtract(CurvePoint::ORDER, -(c | static_cast<uint32_t>(x >= CurvePoint::ORDER)));
			assert(x < CurvePoint::ORDER);
		}
	}
	
	
	Ecdsa() {}  // Not instantiable
	
};
