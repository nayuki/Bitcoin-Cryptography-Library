/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include <cstring>
#include "Base58Check.hpp"
#include "Sha256.hpp"
#include "Sha256Hash.hpp"
#include "Utils.hpp"

using std::uint8_t;
using std::uint32_t;
using std::size_t;



/*---- Public and private functions for bytes-to-Base58 conversion ----*/

void Base58Check::pubkeyHashToBase58Check(const uint8_t pubkeyHash[Ripemd160::HASH_LEN], uint8_t version, char outStr[36]) {
	assert(pubkeyHash != nullptr && outStr != nullptr);
	constexpr size_t arrayLen = 1 + static_cast<size_t>(Ripemd160::HASH_LEN) + 4;
	uint8_t toEncode[arrayLen];
	toEncode[0] = version;
	std::memcpy(&toEncode[1], pubkeyHash, Ripemd160::HASH_LEN);
	uint8_t temp[arrayLen];
	bytesToBase58Check(toEncode, temp, arrayLen - 4, outStr);
}


void Base58Check::privateKeyToBase58Check(const Uint256 &privKey, uint8_t version, bool isCompressed, char outStr[53]) {
	assert(outStr != nullptr);
	constexpr size_t arrayLen = 1 + 32 + 1 + 4;
	uint8_t toEncode[arrayLen];
	toEncode[0] = version;
	privKey.getBigEndianBytes(&toEncode[1]);
	toEncode[33] = 0x01;  // Compressed marker
	uint8_t temp[arrayLen];
	bytesToBase58Check(toEncode, temp, arrayLen - (isCompressed ? 4 : 5), outStr);
}


void Base58Check::extendedPrivateKeyToBase58Check(const ExtendedPrivateKey &key, char outStr[112]) {
	assert(outStr != nullptr);
	constexpr size_t arrayLen = 4 + 1 + 4 + 4 + 32 + 1 + 32 + 4;
	uint8_t toEncode[arrayLen];
	Utils::storeBigUint32(0x0488ADE4, &toEncode[0]);
	toEncode[ 4] = key.depth;
	std::memcpy(&toEncode[5], key.parentPubkeyHash, sizeof(key.parentPubkeyHash));
	Utils::storeBigUint32(key.index, &toEncode[9]);
	std::memcpy(&toEncode[13], key.chainCode, sizeof(key.chainCode));
	toEncode[45] = 0x00;
	key.privateKey.getBigEndianBytes(&toEncode[46]);
	uint8_t temp[arrayLen];
	bytesToBase58Check(toEncode, temp, arrayLen - 4, outStr);
}


void Base58Check::bytesToBase58Check(uint8_t data[], uint8_t temp[], size_t dataLen, char *outStr) {
	// Append 4-byte hash
	assert(data != nullptr && temp != nullptr && outStr != nullptr);
	const Sha256Hash sha256Hash = Sha256::getDoubleHash(data, dataLen);
	for (int i = 0; i < 4; i++, dataLen++)
		data[dataLen] = sha256Hash.value[i];
	
	// Count leading zero bytes
	size_t leadingZeros = 0;
	while (leadingZeros < dataLen && data[leadingZeros] == 0)
		leadingZeros++;
	
	// Encode to Base 58
	size_t outLen = 0;
	while (!isZero(data, dataLen)) {  // Extract digits in little-endian
		outStr[outLen] = ALPHABET[mod58(data, dataLen)];
		outLen++;
		divide58(data, temp, dataLen);  // temp = floor(data / 58)
		Utils::copyBytes(data, temp, dataLen);  // data = temp
	}
	for (size_t i = 0; i < leadingZeros; i++) {  // Append leading zeros
		outStr[outLen] = ALPHABET[0];
		outLen++;
	}
	outStr[outLen] = '\0';
	
	// Reverse the string
	if (outLen == 0)
		return;  // Exit early to ensure that j does not overflow
	for (size_t i = 0, j = outLen - 1; i < j; i++, j--) {
		char tp = outStr[i];
		outStr[i] = outStr[j];
		outStr[j] = tp;
	}
}


bool Base58Check::isZero(const uint8_t x[], size_t len) {
	assert(len == 0 || x != nullptr);
	for (size_t i = 0; i < len; i++) {
		if (x[i] != 0)
			return false;
	}
	return true;
}


uint8_t Base58Check::mod58(const uint8_t x[], size_t len) {
	assert(len == 0 || x != nullptr);
	unsigned int sum = 0;
	for (size_t i = 0; i < len; i++)
		sum = ((sum * 24) + x[i]) % 58;  // Note: 256 % 58 = 24
	return static_cast<uint8_t>(sum);
}


void Base58Check::divide58(const uint8_t x[], uint8_t y[], size_t len) {
	assert(x != nullptr && y != nullptr);
	std::memset(y, 0, len);
	unsigned int dividend = 0;
	for (size_t i = 0; i < len; i++) {  // For each input and output byte
		assert(dividend < 58);
		dividend = (dividend << 8) | x[i];  // Shift next byte into right side
		assert(dividend < 14848);
		y[i] = static_cast<uint8_t>(dividend / 58);
		dividend %= 58;
	}
}



/*---- Public and private functions for Base58-to-bytes conversion ----*/

bool Base58Check::pubkeyHashFromBase58Check(const char *addrStr, uint8_t outPubkeyHash[Ripemd160::HASH_LEN], uint8_t *outVersion) {
	// Preliminary checks
	assert(addrStr != nullptr && outPubkeyHash != nullptr);
	if (std::strlen(addrStr) < 25 || std::strlen(addrStr) > 35)
		return false;
	
	// Perform Base58 decoding
	uint8_t decoded[1 + Ripemd160::HASH_LEN + 4];
	if (!base58CheckToBytes(addrStr, decoded, sizeof(decoded) / sizeof(decoded[0])))
		return false;
	
	// Successfully set the output and version
	std::memcpy(outPubkeyHash, &decoded[1], Ripemd160::HASH_LEN * sizeof(uint8_t));
	if (outVersion != nullptr)
		*outVersion = decoded[0];
	return true;
}


bool Base58Check::privateKeyFromBase58Check(const char wifStr[53], Uint256 &outPrivKey, uint8_t *outVersion, bool *outIsCompressed) {
	// Preliminary checks
	assert(wifStr != nullptr);
	if (std::strlen(wifStr) < 38 || std::strlen(wifStr) > 52)
		return false;
	
	// Perform Base58 decoding
	constexpr size_t arrayLen = 1 + 32 + 1 + 4;
	uint8_t decoded[arrayLen];
	if (base58CheckToBytes(wifStr, decoded, arrayLen - 1)) {  // Try decoding uncompressed
		if (outIsCompressed != nullptr)
			*outIsCompressed = false;
	} else if (base58CheckToBytes(wifStr, decoded, arrayLen)) {  // Try decoding compressed
		if (decoded[33] != 0x01)  // Check compressed marker byte
			return false;
		if (outIsCompressed != nullptr)
			*outIsCompressed = true;
	} else
		return false;
	
	// Successfully set the value and version
	outPrivKey = Uint256(&decoded[1]);
	if (outVersion != nullptr)
		*outVersion = decoded[0];
	return true;
}


bool Base58Check::extendedPrivateKeyFromBase58Check(const char xprvStr[112], ExtendedPrivateKey &outKey) {
	// Preliminary checks
	assert(xprvStr != nullptr);
	if (std::strlen(xprvStr) != 111)
		return false;
	
	// Perform Base58 decoding
	uint8_t decoded[4 + 1 + 4 + 4 + 32 + 1 + 32 + 4];
	if (!base58CheckToBytes(xprvStr, decoded, sizeof(decoded) / sizeof(decoded[0])))
		return false;
	
	// Load fields
	uint8_t depth = decoded[4];
	const uint8_t *parentPubkeyHash = &decoded[5];
	uint32_t index = static_cast<uint32_t>(decoded[ 9]) << 24
	               | static_cast<uint32_t>(decoded[10]) << 16
	               | static_cast<uint32_t>(decoded[11]) <<  8
	               | static_cast<uint32_t>(decoded[12]) <<  0;
	const uint8_t *chainCode = &decoded[13];
	Uint256 privateKey(&decoded[46]);
	
	// Check format
	if (decoded[0] != 0x04 || decoded[1] != 0x88 || decoded[2] != 0xAD || decoded[3] != 0xE4)  // Header for Bitcoin
		return false;
	if (decoded[45] != 0)  // Version byte for Bitcoin
		return false;
	if (privateKey == Uint256::ZERO || privateKey >= CurvePoint::ORDER)
		return false;
	
	// Successfully set the value
	outKey = ExtendedPrivateKey(privateKey, chainCode, depth, index, parentPubkeyHash);
	return true;
}


bool Base58Check::base58CheckToBytes(const char *inStr, uint8_t outData[], size_t outDataLen) {
	assert(inStr != nullptr && outData != nullptr && outDataLen >= 4);
	
	// Convert from Base 58 to base 256
	std::memset(outData, 0, outDataLen * sizeof(outData[0]));
	for (size_t i = 0; inStr[i] != '\0'; i++) {
		if (multiply58(outData, outDataLen))
			return false;
		const char *p = std::strchr(ALPHABET, inStr[i]);
		if (p == nullptr)
			return false;
		if (addUint8(outData, static_cast<uint8_t>(p - &ALPHABET[0]), outDataLen))
			return false;
	}
	
	// Verify number of leading zeros
	for (size_t i = 0; ; i++) {
		if (inStr[i] != '1' && (i >= outDataLen || outData[i] != 0))
			break;  // Success
		else if (inStr[i] == '1' && i < outDataLen && outData[i] == 0)
			continue;  // Keep scanning
		else
			return false;  // Mismatch
	}
	
	// Compute and check hash
	const Sha256Hash sha256Hash = Sha256::getDoubleHash(outData, outDataLen - 4);
	for (unsigned int i = 0; i < 4; i++) {
		if (outData[outDataLen - 4 + i] != sha256Hash.value[i])
			return false;
	}
	return true;
}


bool Base58Check::addUint8(uint8_t x[], uint8_t y, size_t len) {
	assert(len >= 1 && x != nullptr);
	int carry = 0;
	for (size_t i = len - 1; ; i--) {
		int sum = x[i] + carry;
		assert(0 <= sum && sum <= 256);
		if (i == len - 1)
			sum += y;
		x[i] = static_cast<uint8_t>(sum);
		carry = sum >> 8;
		assert((carry >> 1) == 0);
		if (i == 0)
			break;
	}
	return carry > 0;
}


bool Base58Check::multiply58(uint8_t x[], size_t len) {
	assert(len >= 1 && x != nullptr);
	int carry = 0;
	for (size_t i = len - 1; ; i--) {
		int temp = x[i] * 58 + carry;
		x[i] = static_cast<uint8_t>(temp);
		carry = temp >> 8;
		assert(0 <= carry && carry < 58);
		if (i == 0)
			break;
	}
	return carry > 0;
}



/*---- Miscellaneous definitions ----*/

// Static initializers
const char *Base58Check::ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
