# 
# This script calculates and prints the approximate number of 32-bit arithmetic operations
# needed to perform elliptic curve point multiplication, in the C++ implementation.
# For Python 2 and 3. Run with no arguments.
# 
# Bitcoin cryptography library
# Copyright (c) Project Nayuki
# 
# http://www.nayuki.io/page/bitcoin-cryptography-library
# https://github.com/nayuki/Bitcoin-Cryptography-Library
# 


# ---- Calculate operation counts ----

# Uint256 methods
uiCopy        = 1 + 8*2
uiReplace     = 1 + 8*4
uiEquals      = 1 + 3 + 8*2
uiLessThan    = 1 + 2 + 8*6
uiAdd         = 1 + 3 + 8*9
uiSubtract    = 1 + 3 + 8*9
uiShiftLeft1  = 1 + 2 + 8*4
uiShiftRight1 = 1 + 6 + 8*8

# FieldInt methods
fiCopy       = 1 + uiCopy
fiReplace    = 1 + uiReplace
fiSwap       = 1 + 8*7
fiEquals     = 1 + uiEquals
fiLessThan   = 1 + uiLessThan
fiAdd        = 1 + 3 + fiLessThan + uiAdd + uiSubtract
fiSubtract   = 1 + 1 + uiSubtract + uiAdd
fiNegate     = 1 + 4 + 8*9 + fiEquals
fiMultiply2  = 1 + 3 + uiShiftLeft1 + uiSubtract
fiMultiply   = 1 + 754 + (1 + 24*28) + (1 + 16*26) + (1 + 9*8) + 10 + 3 + uiLessThan + uiSubtract
fiSquare     = 1 + fiMultiply
fiReciprocal = 1 + 4*fiCopy + fiReplace + 512*(11 + 2*fiSwap + 2*uiShiftRight1 + 2*uiAdd + 2*uiSubtract)

# CurvePoint methods
cpCopy      = 1 + 3*fiCopy
cpReplace   = 1 + 3*fiReplace
cpIsZero    = 1 + 2 + 3*fiEquals
cpEquals    = 1 + 1 + 3*fiEquals
cpTwice     = 1 + 1 + 10*fiCopy + fiEquals + fiAdd + 3*fiSubtract + 4*fiSquare + 5*fiMultiply2 + 7*fiMultiply + cpIsZero + cpReplace
cpAdd       = 1 + 10 + 10*fiCopy + 3*fiReplace + 2*fiEquals + fiAdd + 5*fiSubtract + 2*fiSquare + 13*fiMultiply + cpCopy + 3*cpReplace + 2*cpIsZero + cpTwice
cpMultiply  = 1 + 18*cpCopy + cpTwice + 13*(cpCopy + cpAdd) + 64*(36 + cpCopy + 16*cpReplace + 4*cpTwice + cpAdd) - 4*cpTwice
cpNormalize = 1 + 1 + fiCopy + 2*fiReplace + 3*fiEquals + 2*fiMultiply + fiReciprocal + cpCopy + cpReplace


# ---- Print numbers ----

vargroups = [
	["uiCopy", "uiReplace", "uiEquals", "uiLessThan", "uiAdd", "uiSubtract", "uiShiftLeft1", "uiShiftRight1"],
	["fiCopy", "fiReplace", "fiSwap", "fiEquals", "fiLessThan", "fiAdd", "fiSubtract", "fiNegate", "fiMultiply2", "fiMultiply", "fiSquare", "fiReciprocal"],
	["cpCopy", "cpReplace", "cpIsZero", "cpEquals", "cpTwice", "cpAdd", "cpMultiply", "cpNormalize"],
]

def inttostr_with_groups(x):
	result = str(x)
	for i in range(len(result) - 3, 1, -3):
		result = result[ : i] + " " + result[i : ]
	return result

for group in vargroups:
	for varname in group:
		print("{:>11}  {}".format(inttostr_with_groups(globals()[varname]), varname))
	print("")
