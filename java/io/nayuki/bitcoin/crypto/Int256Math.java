/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package io.nayuki.bitcoin.crypto;

import java.util.Arrays;


/**
 * Performs arithmetic on unsigned 256-bit integers, which are represented as 8 consecutive ints.
 * All uint operations (except reciprocal()) have no restrictions on the input values,
 * whereas all field operations require each input number to be less than the prime modulus.
 */
public final class Int256Math {
	
	/*---- Uint256 conversion functions ----*/
	
	// Parses the given 64-digit hexadecimal string as a uint256 and stores it in the given array at the given offset.
	public static void hexToUint(String hex, int[] val, int off) {
		if (hex == null)
			throw new NullPointerException();
		if (!hex.matches("[0-9a-fA-F]{64}"))
			throw new IllegalArgumentException();
		checkUint(val, off);
		for (int i = 0; i < NUM_WORDS; i++)
			val[off + i] = (int)Long.parseLong(hex.substring((7 - i) * 8, (8 - i) * 8), 16);
	}
	
	
	// Returns a 32-byte array representing the uint256 in the given array at the given offset encoded in big endian.
	public static byte[] uintToBytes(int[] val, int off) {
		checkUint(val, off);
		byte[] result = new byte[NUM_WORDS * 4];
		for (int i = 0; i < result.length; i++)
			result[result.length - 1 - i] = (byte)(val[off + (i >>> 2)] >>> ((i & 3) << 3));
		return result;
	}
	
	
	// Interprets the given 32-byte array as a uint256 encoded in big endian and stores it in the given array at the given offset.
	public static void bytesToUint(byte[] b, int[] val, int off) {
		if (b == null)
			throw new NullPointerException();
		if (b.length != NUM_WORDS * 4)
			throw new IllegalArgumentException();
		checkUint(val, off);
		
		Arrays.fill(val, off, off + NUM_WORDS, 0);
		for (int i = 0; i < b.length; i++)
			val[off + (i >>> 2)] |= (b[b.length - 1 - i] & 0xFF) << ((i & 3) << 3);
	}
	
	
	
	/*---- Uint256 arithmetic functions ----*/
	
	// Computes z = (x + (y * enable)) mod 2^256, returning a carry-out of 0 or 1.
	// Enable must be 0 or 1. Offsets must be multiples of 8 and can overlap.
	// Constant-time with respect to both values and the enable.
	public static int uintAdd(int[] val, int xOff, int yOff, int enableY, int zOff) {
		checkUint(val, xOff);
		checkUint(val, yOff);
		checkUint(val, zOff);
		checkEnable(enableY);
		
		long mask = LONG_MASK & -enableY;
		int carry = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			long sum = (val[xOff + i] & LONG_MASK) + (val[yOff + i] & mask) + carry;
			val[zOff + i] = (int)sum;
			carry = (int)(sum >>> 32);
			assert (carry >>> 1) == 0;
		}
		return carry;
	}
	
	
	// Computes z = (x - (y * enable)) mod 2^256, returning a borrow-out of 0 or 1.
	// Enable must be 0 or 1. Offsets must be multiples of 8 and can overlap.
	// Constant-time with respect to both values and the enable.
	public static int uintSubtract(int[] val, int xOff, int yOff, int enableY, int zOff) {
		checkUint(val, xOff);
		checkUint(val, yOff);
		checkUint(val, zOff);
		checkEnable(enableY);
		
		long mask = LONG_MASK & -enableY;
		int borrow = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			long diff = (val[xOff + i] & LONG_MASK) - (val[yOff + i] & mask) - borrow;
			val[zOff + i] = (int)diff;
			borrow = -(int)(diff >>> 32);
			assert (borrow >>> 1) == 0;
		}
		return borrow;
	}
	
	
	// Computes z = (x << 1) mod 2^256, returning the old leftmost bit of 0 or 1.
	// Offsets must be multiples of 8 and can overlap. Constant-time with respect to the value.
	public static int uintShiftLeft1(int[] val, int xOff, int zOff) {
		checkUint(val, xOff);
		checkUint(val, zOff);
		int prev = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			int cur = val[xOff + i];
			val[zOff + i] = cur << 1 | prev >>> 31;
			prev = cur;
		}
		return prev >>> 31;
	}
	
	
	// Computes y = (x >>> 1), which is the same as dividing by 2 and flooring.
	// Enable must be 0 or 1. Offsets must be multiples of 8 and can overlap.
	// Constant-time with respect to the value and the enable.
	public static void uintShiftRight1(int[] val, int xOff, int enableShift, int zOff) {
		checkUint(val, xOff);
		checkUint(val, zOff);
		checkEnable(enableShift);
		
		int mask = -enableShift;
		int cur = val[xOff];
		int i;
		for (i = 0; i < NUM_WORDS - 1; i++) {
			int next = val[xOff + i + 1];
			val[zOff + i] = ((cur >>> 1 | next << 31) & mask) | (cur & ~mask);
			cur = next;
		}
		val[zOff + i] = ((cur >>> 1) & mask) | (cur & ~mask);
	}
	
	
	// Computes z = x^-1 mod y. If x == 0, then the reciprocal is 0.
	// The modulus y must be odd and coprime to x. x must be less than the modulus.
	// Requires 48 words of temporary space. Constant-time with respect to both values.
	public static void reciprocal(int[] val, int xOff, int yOff, int zOff, int tempOff) {
		checkUint(val, xOff);
		checkUint(val, yOff);
		checkUint(val, zOff);
		checkUint(val, tempOff);
		assert val.length - tempOff >= 6 * NUM_WORDS;
		if ((val[yOff] & 1) == 0)
			throw new IllegalArgumentException("Modulus must be odd");
		
		// Extended binary GCD algorithm
		int aOff = tempOff + 0 * NUM_WORDS;
		int bOff = tempOff + 1 * NUM_WORDS;
		int cOff = tempOff + 2 * NUM_WORDS;
		int dOff = tempOff + 3 * NUM_WORDS;
		int halfModOff = tempOff + 4 * NUM_WORDS;
		int oneOff = tempOff + 5 * NUM_WORDS;
		System.arraycopy(val, yOff, val, aOff, NUM_WORDS);  // Must be odd
		System.arraycopy(val, xOff, val, bOff, NUM_WORDS);  // Odd or even, and must be less than modulus
		System.arraycopy(ZERO, 0,   val, cOff, NUM_WORDS);
		System.arraycopy(ONE , 0,   val, dOff, NUM_WORDS);
		System.arraycopy(ONE, 0, val, oneOff, NUM_WORDS);
		uintAdd(val, yOff, oneOff, 1, halfModOff);
		uintShiftRight1(val, halfModOff, 1, halfModOff);
		
		// Loop invariant: a = c*x mod y, and b = d*x mod y
		for (int i = 0; i < NUM_WORDS * 32 * 2; i++) {
			// Try to reduce a trailing zero of y. Pseudocode:
			// if (b % 2 == 0) {
			//     b /= 2;
			//     d = d % 2 == 0 ? d / 2 : y - (y - d) / 2;
			// }
			int yEven = ~val[bOff] & 1;
			int bOdd = val[dOff] & 1;
			uintShiftRight1(val, bOff, yEven, bOff);
			uintShiftRight1(val, dOff, yEven, dOff);
			uintAdd(val, dOff, halfModOff, yEven & bOdd, dOff);
			
			// If allowed, try to swap so that b >= a and then do b -= a. Pseudocode:
			// if (b % 2 != 0 && b != 1) {
			//     if (a > b) {
			//         a, b = b, a;
			//         c, d = d, c;
			//     }
			//     b -= a;
			//     d -= c;
			// }
			int enable = val[bOff] & ~equalTo(val, bOff, oneOff) & 1;
			int doswap = enable & lessThan(val, bOff, aOff);
			swap(val, aOff, bOff, doswap);
			uintSubtract(val, bOff, aOff, enable, bOff);
			swap(val, cOff, dOff, doswap);
			int borrow = uintSubtract(val, dOff, cOff, enable, dOff);
			uintAdd(val, dOff, yOff, borrow, dOff);
		}
		System.arraycopy(ZERO, 0, val, tempOff, NUM_WORDS);  // Reuses space
		replace(val, dOff, tempOff, isZero(val, xOff));
		System.arraycopy(val, dOff, val, zOff, NUM_WORDS);
	}
	
	
	/*---- Field arithmetic functions ----*/
	
	// Computes z = (x + y) mod prime. Offsets must be multiples of 8 and can overlap.
	// Requires 8 words of temporary space. Constant-time with respect to both values.
	public static void fieldAdd(int[] val, int xOff, int yOff, int zOff, int tempOff) {
		checkFieldInt(val, xOff);
		checkFieldInt(val, yOff);
		checkUint(val, zOff);
		checkUint(val, tempOff);
		
		int c = uintAdd(val, xOff, yOff, 1, zOff);  // Perform addition
		assert (c >>> 1) == 0;
		System.arraycopy(FIELD_MODULUS, 0, val, tempOff, NUM_WORDS);
		int enable = c | (lessThan(val, zOff, tempOff) ^ 1);
		uintSubtract(val, zOff, tempOff, enable, zOff);  // Conditionally subtract modulus
	}
	
	
	// Computes z = (x - y) mod prime. Offsets must be multiples of 8 and can overlap.
	// Requires 8 words of temporary space. Constant-time with respect to both values.
	public static void fieldSubtract(int[] val, int xOff, int yOff, int zOff, int tempOff) {
		checkFieldInt(val, xOff);
		checkFieldInt(val, yOff);
		checkUint(val, zOff);
		checkUint(val, tempOff);
		
		int b = uintSubtract(val, xOff, yOff, 1, zOff);  // Perform subtraction
		assert (b >>> 1) == 0;
		System.arraycopy(FIELD_MODULUS, 0, val, tempOff, NUM_WORDS);
		uintAdd(val, zOff, tempOff, b, zOff);  // Conditionally add modulus
	}
	
	
	// Computes z = (x * 2) mod prime. Offsets must be multiples of 8 and can overlap.
	// Requires 8 words of temporary space. Constant-time with respect to the value.
	public static void fieldMultiply2(int[] val, int xOff, int zOff, int tempOff) {
		checkFieldInt(val, xOff);
		checkUint(val, zOff);
		checkUint(val, tempOff);
		
		int c = uintShiftLeft1(val, xOff, zOff);
		assert (c >>> 1) == 0;
		System.arraycopy(FIELD_MODULUS, 0, val, tempOff, NUM_WORDS);
		int enable = c | (lessThan(val, zOff, tempOff) ^ 1);
		uintSubtract(val, zOff, tempOff, enable, zOff);  // Conditionally subtract modulus
	}
	
	
	// Computes z = x^2 mod prime. Offsets must be multiples of 8 and can overlap.
	// Requires 40 words of temporary space. Constant-time with respect to the value.
	public static void fieldSquare(int[] val, int xOff, int zOff, int tempOff) {
		fieldMultiply(val, xOff, xOff, zOff, tempOff);
	}
	
	
	// Computes z = (x * y) mod prime. Offsets must be multiples of 8 and can overlap.
	// Requires 40 words of temporary space. Constant-time with respect to both values.
	public static void fieldMultiply(int[] val, int xOff, int yOff, int zOff, int tempOff) {
		checkFieldInt(val, xOff);
		checkFieldInt(val, yOff);
		checkUint(val, zOff);
		checkUint(val, tempOff);
		assert val.length - tempOff >= 5 * NUM_WORDS;
		
		// Compute raw product of (uint256 this->value) * (uint256 other.value) = (uint512 product0), via long multiplication
		int product0Off = tempOff + 0 * NUM_WORDS;  // Uses 16 words
		{
			long carry = 0;
			int i;
			for (i = 0; i < NUM_WORDS * 2 - 1; i++) {
				long sum = carry;
				int c = 0;
				if (i < NUM_WORDS) {
					for (int j = 0; j <= i; j++) {
						long prod = (val[xOff + j] & LONG_MASK) * (val[yOff + i - j] & LONG_MASK);
						sum += prod;
						c += lessThan(sum, prod);
					}
				} else {
					for (int j = NUM_WORDS - 1; j >= 0 && i - j < NUM_WORDS; j--) {
						long prod = (val[xOff + i - j] & LONG_MASK) * (val[yOff + j] & LONG_MASK);
						sum += prod;
						c += lessThan(sum, prod);
					}
				}
				assert 0 <= c && c <= NUM_WORDS;
				val[product0Off + i] = (int)sum;
				carry = (long)c << 32 | sum >>> 32;
			}
			val[product0Off + i] = (int)carry;
			assert (carry >>> 32) == 0;
		}
		
		// Barrett reduction algorithm begins here (see http://www.nayuki.io/page/barrett-reduction-algorithm).
		// Multiply by floor(2^512 / MODULUS), which is 2^256 + 2^32 + 0x3D1. Guaranteed to fit in a uint768.
		int product1Off = tempOff + 2 * NUM_WORDS;  // Uses 24 words
		{
			int carry = 0;
			for (int i = 0; i < NUM_WORDS * 3; i++) {
				long sum = carry;
				if (i < NUM_WORDS * 2)
					sum += (val[product0Off + i] & LONG_MASK) * 0x3D1;
				if (i >= 1 && i < NUM_WORDS * 2 + 1)
					sum += val[product0Off + i - 1] & LONG_MASK;
				if (i >= NUM_WORDS)
					sum += val[product0Off + i - NUM_WORDS] & LONG_MASK;
				val[product1Off + i] = (int)sum;
				carry = (int)(sum >>> 32);
				assert 0 <= carry && carry <= 0x3D3;
			}
			assert carry == 0;
		}
		
		// Virtually shift right by 512 bits, then multiply by MODULUS.
		// Note that MODULUS = 2^256 - 2^32 - 0x3D1. Result fits in a uint512.
		int p1Shift = product1Off + NUM_WORDS * 2;  // Has 8 words
		int product2Off = product1Off;  // Uses 16 words, reuses space
		{
			int borrow = 0;
			for (int i = 0; i < NUM_WORDS * 2; i++) {
				long diff = -borrow;
				if (i < NUM_WORDS)
					diff -= (val[p1Shift + i] & LONG_MASK) * 0x3D1;
				if (i >= 1 && i < NUM_WORDS + 1)
					diff -= val[p1Shift + i - 1] & LONG_MASK;
				if (i >= NUM_WORDS)
					diff += val[p1Shift + i - NUM_WORDS] & LONG_MASK;
				val[product2Off + i] = (int)diff;
				borrow = -(int)(diff >>> 32);
				assert 0 <= borrow && borrow <= 0x3D3;
			}
			assert borrow == 0;
		}
		
		// Compute product0 - product2, which fits in a uint257 (sic)
		int differenceOff = product0Off;  // Uses 9 words but we allocate 16, reuses spaces
		{
			int borrow = 0;
			for (int i = 0; i < NUM_WORDS + 1; i++) {
				long diff = (val[product0Off + i] & LONG_MASK) - (val[product2Off + i] & LONG_MASK) - borrow;
				val[differenceOff + i] = (int)diff;
				borrow = -(int)(diff >>> 32);
				assert (borrow >>> 1) == 0;
			}
		}
		
		// Final conditional subtraction to yield a FieldInt value
		System.arraycopy(val, differenceOff, val, zOff, NUM_WORDS);
		System.arraycopy(FIELD_MODULUS, 0, val, tempOff + 2 * NUM_WORDS, NUM_WORDS);  // Reuses space at offset 16
		int enable = (equalTo(val[differenceOff + NUM_WORDS], 0) & lessThan(val, zOff, tempOff + 2 * NUM_WORDS)) ^ 1;
		uintSubtract(val, zOff, tempOff + 2 * NUM_WORDS, enable, zOff);
	}
	
	
	/*---- Miscellaneous functions ----*/
	
	// Copies the value y into x iff enable is 1. Offsets must be multiples of 8 and can overlap.
	// Constant-time with respect to both values and the enable.
	public static void replace(int[] val, int xOff, int yOff, int enable) {
		checkUint(val, xOff);
		checkUint(val, yOff);
		checkEnable(enable);
		
		int mask = -enable;
		for (int i = 0; i < NUM_WORDS; i++)
			val[xOff + i] = (val[yOff + i] & mask) | (val[xOff + i] & ~mask);
	}
	
	
	// Swaps the values x and y iff enable is 1. Offsets must be multiples of 8 and can overlap.
	// Constant-time with respect to both values and the enable.
	public static void swap(int[] val, int xOff, int yOff, int enable) {
		checkUint(val, xOff);
		checkUint(val, yOff);
		checkEnable(enable);
		
		int mask = -enable;
		for (int i = 0; i < NUM_WORDS; i++) {
			int a = val[xOff + i];
			int b = val[yOff + i];
			val[xOff + i] = (b & mask) | (a & ~mask);
			val[yOff + i] = (a & mask) | (b & ~mask);
		}
	}
	
	
	// Tests x == y and returns 0 or 1. Offsets must be multiples of 8 and can overlap.
	// Constant-time with respect to both values.
	public static int equalTo(int[] val, int xOff, int yOff) {
		checkUint(val, xOff);
		checkUint(val, yOff);
		
		int diff = 0;
		for (int i = 0; i < NUM_WORDS; i++)
			diff |= val[xOff + i] ^ val[yOff + i];
		return ((diff | -diff) >> 31) + 1;
	}
	
	
	// Tests x < y and returns 0 or 1. Offsets must be multiples of 8 and can overlap.
	// Constant-time with respect to both values.
	public static int lessThan(int[] val, int xOff, int yOff) {
		checkUint(val, xOff);
		checkUint(val, yOff);
		
		int result = 0;  // Always 0 or 1
		for (int i = 0; i < NUM_WORDS; i++) {
			int a = val[xOff + i];
			int b = val[yOff + i];
			int neq = a ^ b;
			neq = (neq | -neq) >>> 31;  // 0 or 1
			int lt = ((~a & b) | ((~a ^ b) & (a - b))) >>> 31;  // 0 or 1
			result = (~neq & result) | (neq & lt);
		}
		return result;
	}
	
	
	
	/*---- Helper functions ----*/
	
	// Returns 1 if x == y, otherwise 0. Constant-time with respect to both values.
	static int equalTo(int x, int y) {
		int z = x ^ y;
		return ~(z | -z) >>> 31;
	}
	
	
	// Returns 1 if uint64 x < uint64 y, otherwise 0.
	// Constant-time with respect to both values.
	private static int lessThan(long x, long y) {
		return (int)(((~x & y) | ((~x ^ y) & (x - y))) >>> 63);
	}
	
	
	// Returns 1 if uint256 x < uint256 y, otherwise 0.
	// Constant-time with respect to both values.
	private static int lessThan(int[] x, int xOff, int[] y, int yOff) {
		int result = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			int a = x[xOff + i];
			int b = y[yOff + i];
			int neq = a ^ b;
			neq = (neq | -neq) >>> 31;
			int lt = ((~a & b) | ((~a ^ b) & (a - b))) >>> 31;
			result = (~neq & result) | (neq & lt);
		}
		return result;
	}
	
	
	// Returns 1 if uint256 x == 0, otherwise 0. Constant-time with respect to the value.
	static int isZero(int[] val, int xOff) {
		Int256Math.checkUint(val, xOff);
		int result = 0;
		for (int i = 0; i < NUM_WORDS; i++)
			result |= val[xOff + i];
		return ~(result | -result) >>> 31;
	}
	
	
	static void checkEnable(int en) {
		assert (en >>> 1) == 0;
	}
	
	static void checkUint(int[] arr, int off) {
		assert off >= 0 && (off & 7) == 0 && arr.length - off >= NUM_WORDS;
	}
	
	static void checkFieldInt(int[] arr, int off) {
		checkUint(arr, off);
		assert lessThan(arr, off, FIELD_MODULUS, 0) == 1;
	}
	
	
	/*---- Class constants ----*/
	
	static final int NUM_WORDS = 8;
	private static final long LONG_MASK = 0xFFFFFFFFL;
	
	static final int[] ZERO = {0, 0, 0, 0, 0, 0, 0, 0};
	static final int[] ONE  = {1, 0, 0, 0, 0, 0, 0, 0};
	static final int[] FIELD_MODULUS = {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
	
}
