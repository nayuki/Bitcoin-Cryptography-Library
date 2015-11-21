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

# Function call overhead
funcOvh = 1

# Uint256 methods
uiCopy        = funcOvh + 8*2
uiReplace     = funcOvh + 8*4
uiSwap        = funcOvh + 8*7
uiEquals      = funcOvh + 3 + 8*2
uiLessThan    = funcOvh + 2 + 8*6
uiAdd         = funcOvh + 3 + 8*9
uiSubtract    = funcOvh + 3 + 8*9
uiShiftLeft1  = funcOvh + 2 + 8*4
uiShiftRight1 = funcOvh + 6 + 8*8
uiReciprocal  = funcOvh + 4*uiCopy + uiReplace + 512*(11 + 2*uiSwap + 2*uiShiftRight1 + 2*uiAdd + 2*uiSubtract)

# FieldInt methods
fiCopy       = funcOvh + uiCopy
fiReplace    = funcOvh + uiReplace
fiEquals     = funcOvh + uiEquals
fiLessThan   = funcOvh + uiLessThan
fiAdd        = funcOvh + 3 + fiLessThan + uiAdd + uiSubtract
fiSubtract   = funcOvh + 1 + uiSubtract + uiAdd
fiNegate     = funcOvh + 4 + 8*9 + fiEquals
fiMultiply2  = funcOvh + 3 + uiShiftLeft1 + uiSubtract
fiMultiply   = funcOvh + 754 + (1 + 24*28) + (1 + 16*26) + (1 + 9*8) + 10 + 3 + uiLessThan + uiSubtract
fiSquare     = funcOvh + fiMultiply
fiReciprocal = funcOvh + uiReciprocal

# CurvePoint methods
cpCopy      = funcOvh + 3*fiCopy
cpReplace   = funcOvh + 3*fiReplace
cpIsZero    = funcOvh + 2 + 3*fiEquals
cpEquals    = funcOvh + 1 + 3*fiEquals
cpTwice     = funcOvh + 1 + 10*fiCopy + fiEquals + fiAdd + 3*fiSubtract + 4*fiSquare + 5*fiMultiply2 + 7*fiMultiply + cpIsZero + cpReplace
cpAdd       = funcOvh + 10 + 10*fiCopy + 3*fiReplace + 2*fiEquals + fiAdd + 5*fiSubtract + 2*fiSquare + 13*fiMultiply + cpCopy + 3*cpReplace + 2*cpIsZero + cpTwice
cpMultiply  = funcOvh + 18*cpCopy + cpTwice + 13*(cpCopy + cpAdd) + 64*(36 + cpCopy + 16*cpReplace + 4*cpTwice + cpAdd) - 4*cpTwice
cpNormalize = funcOvh + 1 + fiCopy + 2*fiReplace + 3*fiEquals + 2*fiMultiply + fiReciprocal + cpCopy + cpReplace

# Ecdsa methods
edMulModOrder = funcOvh + 1 + 2*uiCopy + 256*(8 + uiAdd + 2*uiSubtract + uiShiftLeft1 + 2*uiLessThan)
edSign        = funcOvh + 4 + 7*uiCopy + uiReplace + uiAdd + 3*uiSubtract + 3*uiEquals + 4*uiLessThan + uiReciprocal + cpCopy + cpMultiply + cpNormalize + 2*edMulModOrder


# ---- Print numbers ----

vargroups = [
	["uiCopy", "uiReplace", "uiSwap", "uiEquals", "uiLessThan", "uiAdd", "uiSubtract", "uiShiftLeft1", "uiShiftRight1", "uiReciprocal"],
	["fiCopy", "fiReplace", "fiEquals", "fiLessThan", "fiAdd", "fiSubtract", "fiNegate", "fiMultiply2", "fiMultiply", "fiSquare", "fiReciprocal"],
	["cpCopy", "cpReplace", "cpIsZero", "cpEquals", "cpTwice", "cpAdd", "cpMultiply", "cpNormalize"],
	["edMulModOrder", "edSign"],
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
