/* 
 * A runnable main program that tests the functionality of class ExtendedPrivateKey.
 * 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include "TestHelper.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include "ExtendedPrivateKey.hpp"
#include "Uint256.hpp"

using std::uint8_t;


int main() {
	int numTestCases = 0;
	const std::uint32_t HARDEN = ExtendedPrivateKey::HARDEN;
	ExtendedPrivateKey master, child;
	
	{
		Uint256 priv("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
		Bytes chain = hexBytes("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
		uint8_t ppkh[4] = {};
		master = ExtendedPrivateKey(priv, chain.data(), 0, 0, ppkh);
	}
	
	child = master.getChildKey(HARDEN | 44);
	assert(child.privateKey == Uint256("EE1E0BD16BE7A49942867FB5E48470E25255F2E2AD0373D2D25DAE444786F096"));
	numTestCases++;
	
	child = child.getChildKey(HARDEN | 0);
	assert(child.privateKey == Uint256("06C1859D27BD395018FCFCDA42D94E7BCC640882DFB0FFFE96089C908DBDB28C"));
	numTestCases++;
	
	child = child.getChildKey(HARDEN | 0);
	assert(child.privateKey == Uint256("B6956AE327F4396F1C9DE1EB4B8D750F9B37639B93C112100B543723C4781557"));
	numTestCases++;
	
	child = child.getChildKey(0);
	assert(child.privateKey == Uint256("A43AFB4645AF3D89B5DE5EC4FF5D16FFA5935D10CC132E6FC772CC069C46B0B7"));
	numTestCases++;
	
	child = child.getChildKey(1);
	assert(child.privateKey == Uint256("40A439D20E45DB7977006A796652CA238743C2261D6024FC70DBC71AB62E77BF"));
	numTestCases++;
	
	{
		Uint256 priv("26CC9417B89CD77C4ACDBE2E3CD286070A015D8E380F9CD1244AE103B7D89D81");
		Bytes chain = hexBytes("E3B01A74C45227C555EDE5348162B92FC0F278A593E233FDA6EF64F41C3027E3");
		uint8_t ppkh[4] = {};
		master = ExtendedPrivateKey(priv, chain.data(), 0, 0, ppkh);
	}
	
	child = master.getChildKey(HARDEN | 44);
	assert(child.privateKey == Uint256("1851C97DFAE902B85DD116D92E5A38E75442176EABCA3032EB95E7ED29BBF027"));
	numTestCases++;
	
	child = child.getChildKey(HARDEN | 0);
	assert(child.privateKey == Uint256("80E7F81FCEF47E24C32B024CEDC5FCD1E0FC8B5C95DB080540958519089E4E10"));
	numTestCases++;
	
	child = child.getChildKey(HARDEN | UINT32_C(0x7FFFFFFF));
	assert(child.privateKey == Uint256("CEB5D208995C380E23D263C3AA3377F53FEDD317CA87E0DA20E2CFB92AC33F30"));
	numTestCases++;
	
	child = child.getChildKey(1);
	assert(child.privateKey == Uint256("E9ADAD6FDAE70FED72AEB16721E50A16A2AC6578097A6CFC29A98984CCA396C1"));
	numTestCases++;
	
	child = child.getChildKey(UINT32_C(65536));
	assert(child.privateKey == Uint256("A03A015E0936119558D022514AC8326B340FC69C3266442603A3C212004054E3"));
	numTestCases++;
	
	std::printf("All %d test cases passed\n", numTestCases);
	return EXIT_SUCCESS;
}
