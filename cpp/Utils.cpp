/*
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 *
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cstring>
#include "Utils.hpp"

using std::uint8_t;


int Utils::parseHexDigit(int ch) {
	if ('0' <= ch && ch <= '9')
		return ch - '0';
	else if ('a' <= ch && ch <= 'f')
		return ch - 'a' + 10;
	else if ('A' <= ch && ch <= 'F')
		return ch - 'A' + 10;
	else
		return -1;
}


void Utils::copyBytes(void *dest, const void *src, std::size_t count) {
	if (count > 0)
		std::memmove(dest, src, count);
}


void Utils::storeBigUint32(std::uint32_t x, uint8_t arr[4]) {
	arr[0] = static_cast<uint8_t>(x >> 24);
	arr[1] = static_cast<uint8_t>(x >> 16);
	arr[2] = static_cast<uint8_t>(x >>  8);
	arr[3] = static_cast<uint8_t>(x >>  0);
}
/**
	* @author https://github.com/vincenzopalazzo	
**/
vector<unsigned char> spyCBlock::UtilCrypto::ToHexIntoVectorByte(string &hexData)
{
  LOG(INFO) << "The array Hex is: " << hexData;

  vector<unsigned char> *bytes = new vector<unsigned char>();
  for(unsigned i = 0; i < hexData.length(); i += 2)
  {
      string byteSubString = hexData.substr(i, 2);
      unsigned char byte = (unsigned char)strtol(byteSubString.c_str(), NULL, 16);
      bytes->push_back(byte);

  }
  return *bytes;
}


const char *Utils::HEX_DIGITS = "0123456789abcdef";
