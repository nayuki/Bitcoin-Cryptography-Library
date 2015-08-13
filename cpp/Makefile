# 
# This makefile:
# - builds and runs the test programs in this directory, which check the
#   functionality and correctness of the C++ cryptography implementations.
# - requires a C++11 compiler, because of features like
#   move constructors and libraries like cstdint being used.
# 

# ---- Configuration options ----

CC = g++  # g++ or clang++ are both good
CXXFLAGS = -std=c++11  # Mandatory flags
CXXFLAGS += -Wall -fsanitize=undefined  # Diagnostics
CXXFLAGS += -O1  # Optimization level


# ---- Global targets ----

EXECUTABLES = Base58CheckTest CurvePointTest EcdsaTest FieldIntTest Ripemd160Test Sha256HashTest Sha256Test Sha512Test Uint256Test

# Default build target. This compiles all the test executables and runs them.
all: $(EXECUTABLES)
	for name in $(EXECUTABLES); do echo ./$$name; ./$$name; done

clean:
	rm -f $(EXECUTABLES)

.PHONY: all clean


# ---- Individual executable files ----

Base58CheckTest:  Base58CheckTest.cpp  Base58Check.hpp Sha256.hpp Sha256Hash.hpp TestHelper.hpp Uint256.hpp Utils.hpp
	$(CC) $(CXXFLAGS) -o $@ $<

CurvePointTest:   CurvePointTest.cpp   CurvePoint.hpp FieldInt.hpp TestHelper.hpp Uint256.hpp Utils.hpp
	$(CC) $(CXXFLAGS) -o $@ $<

EcdsaTest:        EcdsaTest.cpp        CurvePoint.hpp Ecdsa.hpp FieldInt.hpp Sha256.hpp Sha256Hash.hpp TestHelper.hpp Uint256.hpp Utils.hpp
	$(CC) $(CXXFLAGS) -o $@ $<

FieldIntTest:     FieldIntTest.cpp     FieldInt.hpp TestHelper.hpp Uint256.hpp Utils.hpp
	$(CC) $(CXXFLAGS) -o $@ $<

Ripemd160Test:    Ripemd160Test.cpp    Ripemd160.hpp TestHelper.hpp
	$(CC) $(CXXFLAGS) -o $@ $<

Sha256HashTest:   Sha256HashTest.cpp   Sha256Hash.hpp TestHelper.hpp Utils.hpp
	$(CC) $(CXXFLAGS) -o $@ $<

Sha256Test:       Sha256Test.cpp       Sha256.hpp Sha256Hash.hpp TestHelper.hpp Utils.hpp
	$(CC) $(CXXFLAGS) -o $@ $<

Sha512Test:       Sha512Test.cpp       Sha512.hpp TestHelper.hpp
	$(CC) $(CXXFLAGS) -o $@ $<

Uint256Test:      Uint256Test.cpp      TestHelper.hpp Uint256.hpp Utils.hpp
	$(CC) $(CXXFLAGS) -o $@ $<
