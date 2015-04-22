# 
# Builds and runs the C++ test programs, which check the
# functionality of the C++ cryptography implementations.
# 
# Bitcoin cryptography library, copyright (c) Project Nayuki
# http://www.nayuki.io/page/bitcoin-cryptography-library
# https://github.com/nayuki/Bitcoin-Cryptography-Library
# 

# ---- Options ----

CC = g++
CCFLAGS = -std=c++11 -O1 -Wall -fsanitize=undefined


# ---- Global targets ----

EXECUTABLES = Base58CheckTest CurvePointTest EcdsaTest FieldIntTest Ripemd160Test Sha256HashTest Sha256Test Sha512Test

# Default build target. This compiles all the test executables and runs them.
all: $(EXECUTABLES)
	./Base58CheckTest
	./CurvePointTest
	./EcdsaTest
	./FieldIntTest
	./Ripemd160Test
	./Sha256HashTest
	./Sha256Test
	./Sha512Test

clean:
	rm -f $(EXECUTABLES)

.PHONY: all clean


# ---- Individual executable files ----

Base58CheckTest:  Base58CheckTest.cpp  Base58Check.h Sha256.h Sha256Hash.h
	$(CC) $(CCFLAGS) -o $@ $<

CurvePointTest:   CurvePointTest.cpp   CurvePoint.h FieldInt.h Uint256.h
	$(CC) $(CCFLAGS) -o $@ $<

EcdsaTest:        EcdsaTest.cpp        CurvePoint.h Ecdsa.h FieldInt.h Sha256Hash.h Uint256.h
	$(CC) $(CCFLAGS) -o $@ $<

FieldIntTest:     FieldIntTest.cpp     FieldInt.h Uint256.h
	$(CC) $(CCFLAGS) -o $@ $<

Ripemd160Test:    Ripemd160Test.cpp    Ripemd160.h
	$(CC) $(CCFLAGS) -o $@ $<

Sha256HashTest:   Sha256HashTest.cpp   Sha256Hash.h
	$(CC) $(CCFLAGS) -o $@ $<

Sha256Test:       Sha256Test.cpp       Sha256.h Sha256Hash.h
	$(CC) $(CCFLAGS) -o $@ $<

Sha512Test:       Sha512Test.cpp       Sha512.h
	$(CC) $(CCFLAGS) -o $@ $<
