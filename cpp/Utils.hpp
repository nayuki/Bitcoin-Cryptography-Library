/*
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 *
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <vector>


/*
 * Miscellaneous utilities used in a variety of places.
 */
class Utils final {

	public: static const char *HEX_DIGITS;


	// Returns the numerical value of a hexadecimal digit character
	// (e.g. '9' -> 9, 'a' -> 10, 'B' -> 11), or -1 if the character is invalid.
	public: static int parseHexDigit(int ch);


	// A safe wrapper over memmove() to avoid undefined behavior. This function can be a drop-in replacement
	// for both memcpy() and memmove(). It is useful when count is a variable number that is sometimes zero.
	// Note that src and dest can overlap.
	// The function returns immediately if count is 0. This is safer than calling memmove() with a count of 0, because
	// it would be undefined behavior if src or dest is null, or if either one is pointing to the end of an array.
	// The function is not helpful for code that calls memcpy/memmove with a known positive constant count value.
	public: static void copyBytes(void *dest, const void *src, std::size_t count);

	/**
		* This method conver the string or the string c into vector original bytes
		* this is the procedure for create the hash bitcoin protocol.
		* it's developeing for fix this problem
		* https://bitcoin.stackexchange.com/questions/85571/create-a-double-sha256-block-and-trandaction
		* @author @author https://github.com/vincenzopalazzo
	**/
	public: static vector<unsigned char> ToHexIntoVectorByte(string &hexData);


	public: static void storeBigUint32(std::uint32_t x, std::uint8_t arr[4]);


	Utils() = delete;  // Not instantiable

};
