/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstdint>
#include "CurvePoint.hpp"
#include "Uint256.hpp"


class ExtendedPrivateKey final {
	
	public: static constexpr std::uint32_t HARDEN = UINT32_C(0x80000000);
	
	
	/*---- Fields ----*/
	
	public: Uint256 privateKey;
	public: CurvePoint publicKey;
	
	public: std::uint8_t chainCode[32];
	public: std::uint8_t depth;
	public: std::uint32_t index;
	public: std::uint8_t parentPubkeyHash[4];
	
	
	
	/*---- Constructors ----*/
	
	public: explicit ExtendedPrivateKey();
	
	
	public: explicit ExtendedPrivateKey(
		const Uint256 &privKey, const std::uint8_t chcd[32],
		std::uint8_t dep, uint32_t idx, const std::uint8_t ppkh[4]);
	
	
	
	/*---- Methods ----*/
	
	public: ExtendedPrivateKey getChildKey(std::uint32_t index) const;
	
};
