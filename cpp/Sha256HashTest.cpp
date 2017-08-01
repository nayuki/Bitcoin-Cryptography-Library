/* 
 * A runnable main program that tests the functionality of class Sha256Hash.
 * 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include "TestHelper.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "Sha256Hash.hpp"


int main() {
	// Test equality
	struct TestCase {
		bool matches;
		const char *hexHash;
		Bytes byteHash;
	};
	const vector<TestCase> cases{
		{true , "0000000000000000000000000000000000000000000000000000000000000000", hexBytes("0000000000000000000000000000000000000000000000000000000000000000")},
		{true , "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", hexBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")},
		{true , "00112233445566778899AABBCCDDEEFF0112233445566778899AABBCCDDEEFF0", hexBytes("F0EFDECDBCAB9A897867564534231201FFEEDDCCBBAA99887766554433221100")},
		{true , "FD1A91CA0B85A52ECE4F73EB7C55A5021FA852F78D0390236219EA458C2CE991", hexBytes("91E92C8C45EA19622390038DF752A81F02A5557CEB734FCE2EA5850BCA911AFD")},
		{false, "0000000000000000000000000000000000000000000000000000000000000001", hexBytes("0000000000000000000000000000000000000000000000000000000000000000")},
		{false, "8000000000000000000000000000000000000000000000000000000000000000", hexBytes("0000000000000000000000000000000000000000000000000000000000000000")},
		{false, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF", hexBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")},
	};
	int numTestCases = 0;
	for (const TestCase &tc : cases) {
		assert(std::strlen(tc.hexHash) == Sha256Hash::HASH_LEN * 2 && tc.byteHash.size() == Sha256Hash::HASH_LEN);
		assert((Sha256Hash(tc.byteHash.data(), Sha256Hash::HASH_LEN) == Sha256Hash(tc.hexHash)) == tc.matches);
		numTestCases++;
	}
	
	// Test get byte
	const Sha256Hash hash("FD1A91CA0B85A52ECE4F73EB7C55A5021FA852F78D0390236219EA458C2CE991");
	assert(hash.value[ 0] == 0x91);
	assert(hash.value[ 1] == 0xE9);
	assert(hash.value[ 2] == 0x2C);
	assert(hash.value[30] == 0x1A);
	assert(hash.value[31] == 0xFD);
	numTestCases++;
	
	// Epilog
	std::printf("All %d test cases passed\n", numTestCases);
	return EXIT_SUCCESS;
}
