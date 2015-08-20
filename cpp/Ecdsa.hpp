/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include "Sha256Hash.hpp"
#include "Uint256.hpp"


/* 
 * Computes an ECDSA signature deterministically.
 * Provides just two static methods.
 */
class Ecdsa final {
	
public:
	
	// Computes the signature when given the private key, message hash, and random nonce.
	// Returns true if signing was successful (overwhelming probability), or false if a new nonce must be chosen (vanishing probability).
	// The nonce must be in the range [1, CurvePoint::ORDER). The outputs are unchanged if signing failed.
	// Note: The nonce must be unique, unpredictable, and secret. Otherwise the signature may leak the private key.
	// All successful executions are constant-time with respect to the input values; in order words
	// one successful execution is indistinguishable from another one based on side channel information.
	static bool sign(const Uint256 &privateKey, const Sha256Hash &msgHash, const Uint256 &nonce, Uint256 &outR, Uint256 &outS);
	
	
	// Computes a deterministic nonce based on the HMAC of the message hash with the private key,
	// and then performs ECDSA signing. Returns true iff successful (extremely likely).
	static bool signWithHmacNonce(const Uint256 &privateKey, const Sha256Hash &msgHash, Uint256 &outR, Uint256 &outS);
	
	
private:
	
	// Computes x = (x * y) % order.
	static void multiplyModOrder(Uint256 &x, const Uint256 &y);
	
	
	Ecdsa();  // Not instantiable
	
};
