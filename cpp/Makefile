# 
# This makefile:
# - builds and runs the test programs in this directory, which check the
#   functionality and correctness of the C++ cryptography implementations.
# - requires a C++11 compiler, because of features like
#   move constructors and libraries like cstdint being used.
# 
# Bitcoin cryptography library
# Copyright (c) Project Nayuki
# 
# http://www.nayuki.io/page/bitcoin-cryptography-library
# https://github.com/nayuki/Bitcoin-Cryptography-Library
# 

# ---- Configuration options ----

CC = g++  # g++ or clang++ are both good
CXXFLAGS = -std=c++11  # Mandatory flags
CXXFLAGS += -Wall -fsanitize=undefined  # Diagnostics. Clang also provides -fsanitize=address.
CXXFLAGS += -O1  # Optimization level


# ---- Global targets ----

EXECUTABLES = Base58CheckTest CurvePointTest EcdsaTest FieldIntTest Ripemd160Test Sha256HashTest Sha256Test Sha512Test Uint256Test

# Default build target. This compiles all the test executables and runs them.
all: $(EXECUTABLES)
	for name in $(EXECUTABLES); do echo ./$$name; ./$$name; done

clean:
	rm -f -- $(EXECUTABLES) *.o

.PHONY: all clean


# ---- Executable files ----

Base58CheckTest:  Base58CheckTest.cpp  Base58Check.o Utils.o Sha256Hash.o Sha256.o Uint256.o
	$(CC) $(CXXFLAGS) -o $@ $^

CurvePointTest:   CurvePointTest.cpp   Utils.o Uint256.o FieldInt.o CurvePoint.o
	$(CC) $(CXXFLAGS) -o $@ $^

EcdsaTest:        EcdsaTest.cpp        Utils.o Uint256.o FieldInt.o CurvePoint.o Ecdsa.o Sha256Hash.o Sha256.o
	$(CC) $(CXXFLAGS) -o $@ $^

FieldIntTest:     FieldIntTest.cpp     Utils.o Uint256.o FieldInt.o
	$(CC) $(CXXFLAGS) -o $@ $^

Ripemd160Test:    Ripemd160Test.cpp    Ripemd160.o
	$(CC) $(CXXFLAGS) -o $@ $^

Sha256HashTest:   Sha256HashTest.cpp   Utils.o Sha256Hash.o
	$(CC) $(CXXFLAGS) -o $@ $^

Sha256Test:       Sha256Test.cpp       Utils.o Sha256Hash.o Sha256.o
	$(CC) $(CXXFLAGS) -o $@ $^

Sha512Test:       Sha512Test.cpp       Sha512.o
	$(CC) $(CXXFLAGS) -o $@ $^

Uint256Test:      Uint256Test.cpp      Utils.o Uint256.o
	$(CC) $(CXXFLAGS) -o $@ $^


# ---- Module files ----

Base58Check.o: Base58Check.cpp Base58Check.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

CurvePoint.o: CurvePoint.cpp CurvePoint.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

Ecdsa.o: Ecdsa.cpp Ecdsa.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

FieldInt.o: FieldInt.cpp FieldInt.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

Ripemd160.o: Ripemd160.cpp Ripemd160.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

Sha256.o: Sha256.cpp Sha256.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

Sha256Hash.o: Sha256Hash.cpp Sha256Hash.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

Sha512.o: Sha512.cpp Sha512.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

Uint256.o: Uint256.cpp Uint256.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<

Utils.o: Utils.cpp Utils.hpp
	$(CC) $(CXXFLAGS) -c -o $@ $<
