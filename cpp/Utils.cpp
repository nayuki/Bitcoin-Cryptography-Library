/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cstring>
#include "Utils.hpp"


int Utils::parseHexDigit(int ch) {
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	else if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	else if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	else
		return -1;
}


void Utils::copyBytes(void *dest, const void *src, size_t count) {
	if (count > 0)
		std::memmove(dest, src, count);
}


const char *Utils::HEX_DIGITS = "0123456789abcdef";
