/* 
 * A runnable main program that calculates and prints the approximate
 * number of 32-bit arithmetic operations needed to perform
 * elliptic curve point multiplication, in this C++ implementation.
 * 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string>
#include "CountOps.hpp"
#include "CurvePoint.hpp"
#include "Ecdsa.hpp"
#include "FieldInt.hpp"
#include "Sha256.hpp"
#include "Sha256Hash.hpp"
#include "Uint256.hpp"


static long long opsCount;


void countOps(long n) {
	opsCount += n;
}


static void printOps(const char *name);
static void doUint256();
static void doFieldInt();
static void doCurvePoint();
static void doEcdsa();


int main() {
	doUint256();
	doFieldInt();
	doCurvePoint();
	doEcdsa();
	return EXIT_SUCCESS;
}


static void doUint256() {
	{
		Uint256 x = Uint256::ONE;
		Uint256 y = Uint256::ONE;
		opsCount = 0;
		x.replace(y, 1);
		printOps("uiReplace");
	}
	{
		Uint256 x = Uint256::ONE;
		Uint256 y = Uint256::ONE;
		opsCount = 0;
		x.swap(y, 1);
		printOps("uiSwap");
	}
	{
		Uint256 x = Uint256::ONE;
		Uint256 y = Uint256::ONE;
		opsCount = 0;
		x == y;
		printOps("uiEquals");
	}
	{
		Uint256 x = Uint256::ONE;
		Uint256 y = Uint256::ONE;
		opsCount = 0;
		x < y;
		printOps("uiLessThan");
	}
	{
		Uint256 x = Uint256::ONE;
		Uint256 y = Uint256::ONE;
		opsCount = 0;
		x.add(y);
		printOps("uiAdd");
	}
	{
		Uint256 x = Uint256::ONE;
		Uint256 y = Uint256::ONE;
		opsCount = 0;
		x.subtract(y);
		printOps("uiSubtract");
	}
	{
		Uint256 x = Uint256::ONE;
		opsCount = 0;
		x.shiftLeft1();
		printOps("uiShiftLeft1");
	}
	{
		Uint256 x = Uint256::ONE;
		opsCount = 0;
		x.shiftRight1();
		printOps("uiShiftRight1");
	}
	{
		Uint256 x = Uint256::ONE;
		Uint256 y = CurvePoint::ORDER;
		opsCount = 0;
		x.reciprocal(y);
		printOps("uiReciprocal");
	}
	std::cout << std::endl;
}


static void doFieldInt() {
	{
		FieldInt x(Uint256::ONE);
		FieldInt y(Uint256::ONE);
		opsCount = 0;
		x.replace(y, 1);
		printOps("fiReplace");
	}
	{
		FieldInt x(Uint256::ONE);
		FieldInt y(Uint256::ONE);
		opsCount = 0;
		x == y;
		printOps("fiEquals");
	}
	{
		FieldInt x(Uint256::ONE);
		FieldInt y(Uint256::ONE);
		opsCount = 0;
		x < y;
		printOps("fiLessThan");
	}
	{
		FieldInt x(Uint256::ONE);
		FieldInt y(Uint256::ONE);
		opsCount = 0;
		x.add(y);
		printOps("fiAdd");
	}
	{
		FieldInt x(Uint256::ONE);
		FieldInt y(Uint256::ONE);
		opsCount = 0;
		x.subtract(y);
		printOps("fiSubtract");
	}
	{
		FieldInt x(Uint256::ONE);
		opsCount = 0;
		x.multiply2();
		printOps("fiMultiply2");
	}
	{
		FieldInt x(Uint256::ONE);
		FieldInt y(Uint256::ONE);
		opsCount = 0;
		x.multiply(y);
		printOps("fiMultiply");
	}
	{
		FieldInt x(Uint256::ONE);
		opsCount = 0;
		x.square();
		printOps("fiSquare");
	}
	{
		FieldInt x(Uint256::ONE);
		opsCount = 0;
		x.reciprocal();
		printOps("fiReciprocal");
	}
	std::cout << std::endl;
}


static void doCurvePoint() {
	{
		CurvePoint x = CurvePoint::G;
		CurvePoint y = CurvePoint::G;
		opsCount = 0;
		x.replace(y, 1);
		printOps("cpReplace");
	}
	{
		CurvePoint x = CurvePoint::G;
		opsCount = 0;
		x.isZero();
		printOps("cpIsZero");
	}
	{
		CurvePoint x = CurvePoint::G;
		CurvePoint y = CurvePoint::G;
		opsCount = 0;
		x == y;
		printOps("cpEquals");
	}
	{
		CurvePoint x = CurvePoint::G;
		opsCount = 0;
		x.twice();
		printOps("cpTwice");
	}
	{
		CurvePoint x = CurvePoint::G;
		CurvePoint y = CurvePoint::G;
		opsCount = 0;
		x.add(y);
		printOps("cpAdd");
	}
	{
		CurvePoint x = CurvePoint::G;
		Uint256 y = Uint256::ONE;
		opsCount = 0;
		x.multiply(y);
		printOps("cpMultiply");
	}
	{
		CurvePoint x = CurvePoint::G;
		opsCount = 0;
		x.normalize();
		printOps("cpNormalize");
	}
	{
		CurvePoint x = CurvePoint::G;
		opsCount = 0;
		x.isOnCurve();
		printOps("cpIsOnCurve");
	}
	std::cout << std::endl;
}


static void doEcdsa() {
	{
		Uint256 privKey = Uint256::ONE;
		Sha256Hash msgHash = Sha256::getHash(nullptr, 0);
		Uint256 nonce = Uint256::ONE;
		Uint256 outR, outS;
		opsCount = 0;
		Ecdsa::sign(privKey, msgHash, nonce, outR, outS);
		printOps("edSign");
	}
	{
		CurvePoint pubKey = CurvePoint::G;
		Sha256Hash msgHash = Sha256::getHash(nullptr, 0);
		Uint256 r = Uint256::ONE;
		Uint256 s = Uint256::ONE;
		opsCount = 0;
		Ecdsa::verify(pubKey, msgHash, r, s);
		printOps("edVerify");
	}
	std::cout << std::endl;
}


static void printOps(const char *name) {
	std::string s = std::to_string(opsCount);
	while (s.size() < 9)
		s.insert(0, " ", 1);
	for (std::size_t i = s.size(); i >= 4; i -= 3)
		s.insert(i - 3, " ", 1);
	std::cout << s << "  " << name << std::endl;
}
