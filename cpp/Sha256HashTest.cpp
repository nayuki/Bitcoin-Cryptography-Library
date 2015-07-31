/* 
 * A runnable main program that tests the functionality of class Sha256Hash.
 * 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#undef NDEBUG
#include <cstdio>
#include <cstring>
#include "Sha256Hash.h"
#include "TestHelper.hpp"


struct TestCase {
	const bool matches;
	const char *hexHash;
	const Bytes byteHash;
};


int main(int argc, char **argv) {
	// Test equality
	TestCase cases[] = {
		{true , "0000000000000000000000000000000000000000000000000000000000000000", hexBytes("0000000000000000000000000000000000000000000000000000000000000000")},
		{true , "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", hexBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")},
		{true , "00112233445566778899aabbccddeeff0112233445566778899aabbccddeeff0", hexBytes("F0EFDECDBCAB9A897867564534231201FFEEDDCCBBAA99887766554433221100")},
		{true , "fd1a91ca0b85a52ece4f73eb7c55a5021fa852f78d0390236219ea458c2ce991", hexBytes("91E92C8C45EA19622390038DF752A81F02A5557CEB734FCE2EA5850BCA911AFD")},
		{false, "0000000000000000000000000000000000000000000000000000000000000001", hexBytes("0000000000000000000000000000000000000000000000000000000000000000")},
		{false, "8000000000000000000000000000000000000000000000000000000000000000", hexBytes("0000000000000000000000000000000000000000000000000000000000000000")},
		{false, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff", hexBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")},
	};
	int numTestCases = 0;
	for (unsigned int i = 0; i < ARRAY_LENGTH(cases); i++) {
		TestCase &tc = cases[i];
		assert(strlen(tc.hexHash) == SHA256_HASH_LEN * 2 && tc.byteHash.size() == SHA256_HASH_LEN);
		assert((Sha256Hash(tc.byteHash.data(), SHA256_HASH_LEN) == Sha256Hash(tc.hexHash)) == tc.matches);
		numTestCases++;
	}
	
	// Test get byte
	Sha256Hash hash("fd1a91ca0b85a52ece4f73eb7c55a5021fa852f78d0390236219ea458c2ce991");
	assert(hash.getByte( 0) == 0x91);
	assert(hash.getByte( 1) == 0xE9);
	assert(hash.getByte( 2) == 0x2C);
	assert(hash.getByte(30) == 0x1A);
	assert(hash.getByte(31) == 0xFD);
	numTestCases++;
	
	// Epilog
	printf("All %d test cases passed\n", numTestCases);
	return 0;
}
