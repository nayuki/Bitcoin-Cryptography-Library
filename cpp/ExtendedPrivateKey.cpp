/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cstring>
#include "ExtendedPrivateKey.hpp"
#include "Ripemd160.hpp"
#include "Sha256.hpp"
#include "Sha256Hash.hpp"
#include "Sha512.hpp"
#include "Utils.hpp"

using std::uint8_t;
using std::uint32_t;


ExtendedPrivateKey::ExtendedPrivateKey() :
	privateKey(Uint256::ZERO),
	publicKey(CurvePoint::ZERO),
	chainCode(),
	depth(0),
	index(0),
	parentPubkeyHash() {}


ExtendedPrivateKey::ExtendedPrivateKey(
	const Uint256 &privKey, const uint8_t chcd[32], uint8_t dep, uint32_t idx, const uint8_t ppkh[4]) :
		privateKey(privKey),
		publicKey(CurvePoint::privateExponentToPublicPoint(privKey)),
		depth(dep),
		index(idx) {
	std::memcpy(chainCode, chcd, sizeof(chainCode));
	std::memcpy(parentPubkeyHash, ppkh, sizeof(parentPubkeyHash));
}


ExtendedPrivateKey ExtendedPrivateKey::getChildKey(uint32_t index) const {
	uint8_t msg[37];
	if (index < HARDEN)  // Normal child key
		publicKey.toCompressedPoint(msg);
	else {  // Hardened child key
		msg[0] = 0;
		privateKey.getBigEndianBytes(&msg[1]);
	}
	Utils::storeBigUint32(index, &msg[33]);
	uint8_t hash[Sha512::HASH_LEN];
	Sha512::getHmac(chainCode, sizeof(chainCode) / sizeof(chainCode[0]), msg, sizeof(msg) / sizeof(msg[0]), hash);
	
	Uint256 num(hash);
	if (num >= CurvePoint::ORDER)
		return ExtendedPrivateKey();
	uint32_t carry = num.add(privateKey);
	num.subtract(CurvePoint::ORDER, carry | static_cast<uint32_t>(num >= CurvePoint::ORDER));
	if (num == Uint256::ZERO)
		return ExtendedPrivateKey();
	
	uint8_t pubKeyBytes[33];
	publicKey.toCompressedPoint(pubKeyBytes);
	Sha256Hash innerHash = Sha256::getHash(pubKeyBytes, sizeof(pubKeyBytes) / sizeof(pubKeyBytes[0]));
	uint8_t pubKeyHash[Ripemd160::HASH_LEN];
	Ripemd160::getHash(innerHash.value, Sha256Hash::HASH_LEN, pubKeyHash);
	return ExtendedPrivateKey(num, &hash[32], static_cast<uint8_t>(depth + 1), index, pubKeyHash);
}
