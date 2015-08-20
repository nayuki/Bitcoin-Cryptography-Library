/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once


/* 
 * Miscellaneous utilities used in a variety of places.
 */
class Utils final {
	
public:
	
	static const char *HEX_DIGITS;
	
	
	static int parseHexDigit(int ch);
	
	
private:
	Utils();
	
};
