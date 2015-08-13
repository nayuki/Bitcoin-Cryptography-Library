/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cassert>
#include <cstdint>
#include "CurvePoint.hpp"
#include "FieldInt.hpp"
#include "Sha256.hpp"
#include "Sha256Hash.hpp"
#include "Uint256.hpp"


/* 
 * Computes an ECDSA signature deterministically.
 * Provides just two static methods.
 */
class Ecdsa {
	
public:
	
	// Computes the signature when given the private key, message hash, and random nonce.
	// Returns true if signing was successful (overwhelming probability), or false if a new nonce must be chosen (vanishing probability).
	// The nonce must be in the range [1, CurvePoint::ORDER). The outputs are unchanged if signing failed.
	// Note: The nonce must be unique, unpredictable, and secret. Otherwise the signature may leak the private key.
	// All successful executions are constant-time with respect to the input values; in order words
	// one successful execution is indistinguishable from another one based on side channel information.
	static bool sign(const Uint256 &privateKey, const Sha256Hash &msgHash, const Uint256 &nonce, Uint256 &outR, Uint256 &outS) {
		/* 
		 * Pseudocode:
		 *   if (nonce outside range [1, order-1]) return false;
		 *   p = nonce * G;
		 *   r = p.x % order;
		 *   if (r == 0) return false;
		 *   s = nonce^-1 * (msgHash + r * privateKey) % order;
		 *   if (s == 0) return false;
		 *   s = min(s, order - s);
		 */
		
		const Uint256 &order = CurvePoint::ORDER;
		const Uint256 &zero = Uint256::ZERO;
		if (nonce == zero || nonce >= order)
			return false;
		
		CurvePoint p(CurvePoint::G);
		p.multiply(nonce);
		p.normalize();
		
		Uint256 r;
		for (int i = 0; i < 8; i++)  // Copy raw value from FieldInt to Uint256
			r.value[i] = p.x.value[i];
		r.subtract(order, -static_cast<uint32_t>(r >= order));
		if (r == zero)
			return false;
		assert(r < order);
		
		Uint256 s(r);
		Uint256 z(msgHash.data());
		multiplyModOrder(s, privateKey);
		uint32_t carry = s.add(z, UINT32_C(0xFFFFFFFF));
		s.subtract(order, -(carry | static_cast<uint32_t>(s >= order)));
		
		Uint256 kInv(nonce);
		kInv.reciprocal(order);
		multiplyModOrder(s, kInv);
		if (s == zero)
			return false;
		
		Uint256 negS(order);
		negS.subtract(s);
		s.replace(negS, -static_cast<uint32_t>(negS < s));  // To ensure low S values for BIP 62
		outR = r;
		outS = s;
		return true;
	}
	
	
	// Computes a deterministic nonce based on the HMAC of the message hash with the private key,
	// and then performs ECDSA signing. Returns true iff successful (extremely likely).
	static bool signWithHmacNonce(const Uint256 &privateKey, const Sha256Hash &msgHash, Uint256 &outR, Uint256 &outS) {
		uint8_t privkeyBytes[32] = {};
		uint8_t msgHashBytes[SHA256_HASH_LEN] = {};
		privateKey.getBigEndianBytes(privkeyBytes);
		memcpy(msgHashBytes, msgHash.data(), SHA256_HASH_LEN);
		
		Sha256Hash hmac(Sha256::getHmac(privkeyBytes, sizeof(privkeyBytes), msgHashBytes, sizeof(msgHashBytes)));
		Uint256 nonce(hmac.data());
		return sign(privateKey, msgHash, nonce, outR, outS);
	}
	
	
private:
	
	// Computes x = (x * y) % order.
	static void multiplyModOrder(Uint256 &x, const Uint256 &y) {
		// Russian peasant multiplication with modular reduction at each step
		const Uint256 &mod = CurvePoint::ORDER;
		assert(&x != &y && x < mod);
		const Uint256 copy(x);
		x = Uint256::ZERO;
		for (int i = 255; i >= 0; i--) {
			// Multiply by 2
			uint32_t c = x.shiftLeft1();
			x.subtract(mod, -(c | static_cast<uint32_t>(x >= mod)));
			// Conditionally add 'copy'
			uint32_t mask = -((y.value[i >> 5] >> (i & 31)) & 1);
			c = x.add(copy, mask);
			x.subtract(mod, -(c | static_cast<uint32_t>(x >= mod)));
			assert(x < mod);
		}
	}
	
	
	Ecdsa() {}  // Not instantiable
	
};
