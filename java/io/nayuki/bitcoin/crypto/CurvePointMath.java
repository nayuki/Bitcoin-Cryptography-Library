/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package io.nayuki.bitcoin.crypto;

import static io.nayuki.bitcoin.crypto.Int256Math.NUM_WORDS;
import java.util.Arrays;


/**
 * Performs arithmetic on elliptic curve points, which are represented as 24 consecutive ints.
 * A curve point is a tuple of 3 field integers (x, y, z) in projective coordinates.
 * The ordinary affine coordinates of the point is (x/z, y/z), which can be obtained by normalizing.
 */
public final class CurvePointMath {
	
	/*---- Critical class constants ----*/
	
	static final int POINT_WORDS = 3 * NUM_WORDS;
	
	
	/*---- Arithmetic functions ----*/
	
	// Doubles the given curve point. Requires 64 words of temporary space.
	// The resulting point is usually not normalized. Constant-time with respect to the point.
	public static void twice(int[] val, int pOff, int tempOff) {
		/* 
		 * (See https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates)
		 * Algorithm pseudocode:
		 * if (this == ZERO || y == 0)
		 *   this = ZERO
		 * else {
		 *   a = 0 (curve parameter)
		 *   t = 3 * x^2 + a * z^2
		 *   u = 2 * y * z
		 *   v = 2 * u * x * y
		 *   w = t^2 - 2 * v
		 *   x' = u * w
		 *   y' = t * (v - w) - 2 * (u * y)^2
		 *   z' = u^3
		 * }
		 */
		
		checkPoint(val, pOff);
		Int256Math.checkUint(val, tempOff);
		assert val.length - tempOff >= TWICE_TEMP_WORDS;
		
		int zeroResult = CurvePointMath.isZero(val, pOff) | Int256Math.isZero(val, pOff + YCOORD);
		int newTempOff = tempOff + 3 * NUM_WORDS;
		
		int uOff = tempOff + 0 * NUM_WORDS;
		Int256Math.fieldMultiply(val, pOff + YCOORD, pOff + ZCOORD, uOff, newTempOff);
		Int256Math.fieldMultiply2(val, uOff, uOff, newTempOff);
		
		int vOff = tempOff + 1 * NUM_WORDS;
		Int256Math.fieldMultiply(val, uOff, pOff + XCOORD, vOff, newTempOff);
		Int256Math.fieldMultiply(val, vOff, pOff + YCOORD, vOff, newTempOff);
		Int256Math.fieldMultiply2(val, vOff, vOff, newTempOff);
		
		Int256Math.fieldSquare(val, pOff + XCOORD, pOff + XCOORD, newTempOff);
		int tOff = tempOff + 2 * NUM_WORDS;
		Int256Math.fieldMultiply2(val, pOff + XCOORD, tOff, newTempOff);
		Int256Math.fieldAdd(val, tOff, pOff + XCOORD, tOff, newTempOff);
		
		int wOff = pOff + ZCOORD;  // Reuses space
		Int256Math.fieldSquare(val, tOff, wOff, newTempOff);
		Int256Math.fieldMultiply2(val, vOff, pOff + XCOORD, newTempOff);
		Int256Math.fieldSubtract(val, wOff, pOff + XCOORD, wOff, newTempOff);
		
		Int256Math.fieldSubtract(val, vOff, wOff, pOff + XCOORD, newTempOff);
		Int256Math.fieldMultiply(val, pOff + XCOORD, tOff, pOff + XCOORD, newTempOff);
		Int256Math.fieldMultiply(val, pOff + YCOORD, uOff, pOff + YCOORD, newTempOff);
		Int256Math.fieldSquare(val, pOff + YCOORD, pOff + YCOORD, newTempOff);
		Int256Math.fieldMultiply2(val, pOff + YCOORD, pOff + YCOORD, newTempOff);
		Int256Math.fieldSubtract(val, pOff + XCOORD, pOff + YCOORD, pOff + YCOORD, newTempOff);
		
		Int256Math.fieldMultiply(val, uOff, wOff, pOff + XCOORD, newTempOff);
		
		Int256Math.fieldSquare(val, uOff, pOff + ZCOORD, newTempOff);
		Int256Math.fieldMultiply(val, uOff, pOff + ZCOORD, pOff + ZCOORD, newTempOff);
		
		System.arraycopy(ZERO_POINT, 0, val, tempOff, POINT_WORDS);  // Reuses space
		CurvePointMath.replace(val, pOff, tempOff, zeroResult);
	}
	
	public static final int TWICE_TEMP_WORDS = 3 * NUM_WORDS + Int256Math.FIELD_MULTIPLY_TEMP_WORDS;
	
	
	// Adds the point q into point p. Requires 112 words of temporary space.
	// The resulting point is usually not normalized. Constant-time with respect to both points.
	public static void add(int[] val, int pOff, int qOff, int tempOff) {
		/* 
		 * (See https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates)
		 * Algorithm pseudocode:
		 * if (p == ZERO)
		 *   p = q
		 * else if (q == ZERO)
		 *   p = p
		 * else {
		 *   t0 = p.y * q.z
		 *   t1 = q.y * p.z
		 *   u0 = p.x * q.z
		 *   u1 = q.x * p.z
		 *   if (u0 == u1) {  // Same x coordinates
		 *     if (t0 == t1)  // Same y coordinates
		 *       p = twice(p)
		 *     else
		 *       p = ZERO
		 *   } else {
		 *     t = t0 - t1
		 *     u = u0 - u1
		 *     u2 = u^2
		 *     v = p.z * q.z
		 *     w = t^2 * v - u2 * (u0 + u1)
		 *     p.x' = u * w
		 *     u3 = u2 * u
		 *     p.y' = t * (u0 * u2 - w) - t0 * u3
		 *     p.z' = u3 * v
		 *   }
		 * }
		 */
		
		checkPoint(val, pOff);
		checkPoint(val, qOff);
		Int256Math.checkUint(val, tempOff);
		assert val.length - tempOff >= ADD_TEMP_WORDS;
		
		int pIsZero = CurvePointMath.isZero(val, pOff);
		int qIsZero = CurvePointMath.isZero(val, qOff);
		int rOff = tempOff + 0 * NUM_WORDS;
		System.arraycopy(val, pOff, val, rOff, POINT_WORDS);
		CurvePointMath.twice(val, rOff, tempOff + POINT_WORDS);
		CurvePointMath.replace(val, rOff, pOff, qIsZero);
		CurvePointMath.replace(val, rOff, qOff, pIsZero);
		
		int newTempOff = tempOff + 9 * NUM_WORDS;
		int u0Off = tempOff + 3 * NUM_WORDS;
		int u1Off = tempOff + 4 * NUM_WORDS;
		int t0Off = tempOff + 5 * NUM_WORDS;
		int t1Off = pOff + XCOORD;  // Reuses space
		Int256Math.fieldMultiply(val, pOff + XCOORD, qOff + ZCOORD, u0Off, newTempOff);
		Int256Math.fieldMultiply(val, qOff + XCOORD, pOff + ZCOORD, u1Off, newTempOff);
		Int256Math.fieldMultiply(val, pOff + YCOORD, qOff + ZCOORD, t0Off, newTempOff);
		Int256Math.fieldMultiply(val, qOff + YCOORD, pOff + ZCOORD, t1Off, newTempOff);
		int sameX = Int256Math.equalTo(val, u0Off, u1Off);
		int sameY = Int256Math.equalTo(val, t0Off, t1Off);
		System.arraycopy(ZERO_POINT, 0, val, tempOff + 6 * NUM_WORDS, POINT_WORDS);
		CurvePointMath.replace(val, rOff, tempOff + 6 * NUM_WORDS, (pIsZero ^ 1) & (qIsZero ^ 1) & sameX & (sameY ^ 1));
		
		int tOff = pOff + YCOORD;  // Reuses space
		int uOff = tempOff + 6 * NUM_WORDS;
		int u2Off = tempOff + 7 * NUM_WORDS;
		int vOff = pOff + ZCOORD;  // Reuses space
		Int256Math.fieldSubtract(val, t0Off, t1Off, tOff, newTempOff);
		Int256Math.fieldSubtract(val, u0Off, u1Off, uOff, newTempOff);
		Int256Math.fieldSquare(val, uOff, u2Off, newTempOff);
		Int256Math.fieldMultiply(val, pOff + ZCOORD, qOff + ZCOORD, vOff, newTempOff);
		
		int wOff = tempOff + 8 * NUM_WORDS;
		Int256Math.fieldSquare(val, tOff, wOff, newTempOff);
		Int256Math.fieldMultiply(val, wOff, vOff, wOff, newTempOff);
		Int256Math.fieldAdd(val, u0Off, u1Off, u1Off, newTempOff);
		Int256Math.fieldMultiply(val, u1Off, u2Off, u1Off, newTempOff);
		Int256Math.fieldSubtract(val, wOff, u1Off, wOff, newTempOff);
		
		Int256Math.fieldMultiply(val, uOff, wOff, pOff + XCOORD, newTempOff);
		
		int u3Off = u1Off;  // Reuses space
		Int256Math.fieldMultiply(val, uOff, u2Off, u3Off, newTempOff);
		
		Int256Math.fieldMultiply(val, u0Off, u2Off, u0Off, newTempOff);
		Int256Math.fieldSubtract(val, u0Off, wOff, u0Off, newTempOff);
		Int256Math.fieldMultiply(val, tOff, u0Off, tOff, newTempOff);
		Int256Math.fieldMultiply(val, t0Off, u3Off, t0Off, newTempOff);
		Int256Math.fieldSubtract(val, tOff, t0Off, pOff + YCOORD, newTempOff);
		
		Int256Math.fieldMultiply(val, vOff, u3Off, pOff + ZCOORD, newTempOff);
		
		CurvePointMath.replace(val, pOff, rOff, pIsZero | qIsZero | sameX);
	}
	
	public static final int ADD_TEMP_WORDS = 9 * NUM_WORDS + Int256Math.FIELD_MULTIPLY_TEMP_WORDS;
	
	
	// Multiplies the given point by the given unsigned integer. The resulting point is usually not normalized.
	// Requires 552 words of temporary space. Constant-time with respect to both values.
	public static void multiply(int[] val, int pOff, int nOff, int tempOff) {
		checkPoint(val, pOff);
		Int256Math.checkUint(val, nOff);
		Int256Math.checkUint(val, tempOff);
		assert val.length - tempOff >= MULTIPLY_TEMP_WORDS;
		
		// Precompute [p*0, p*1, ..., p*15]
		final int tableBits = 4;  // Do not modify
		final int tableLen = 1 << tableBits;
		int newTempOff = tempOff + (tableLen + 1) * POINT_WORDS;
		int tableOff = tempOff;  // Uses tableLen * POINT_WORDS elements
		System.arraycopy(ZERO_POINT, 0, val, tableOff, POINT_WORDS);
		System.arraycopy(val, pOff, val, tableOff + 1 * POINT_WORDS, POINT_WORDS);
		System.arraycopy(val, pOff, val, tableOff + 2 * POINT_WORDS, POINT_WORDS);
		CurvePointMath.twice(val, tableOff + 2 * POINT_WORDS, newTempOff);
		for (int i = 3; i < tableLen; i++) {
			System.arraycopy(val, tableOff + (i - 1) * POINT_WORDS, val, tableOff + i * POINT_WORDS, POINT_WORDS);
			CurvePointMath.add(val, tableOff + i * POINT_WORDS, pOff, newTempOff);
		}
		
		// Process tableBits bits per iteration (windowed method)
		System.arraycopy(ZERO_POINT, 0, val, pOff, POINT_WORDS);
		int qOff = tempOff + tableLen * POINT_WORDS;
		for (int i = Int256Math.NUM_WORDS * 32 - tableBits; i >= 0; i -= tableBits) {
			int inc = (val[nOff + (i >>> 5)] >>> (i & 31)) & (tableLen - 1);
			for (int j = 0; j < tableLen; j++)
				CurvePointMath.replace(val, qOff, tableOff + j * POINT_WORDS, Int256Math.equalTo(j, inc));
			CurvePointMath.add(val, pOff, qOff, newTempOff);
			if (i != 0) {
				for (int j = 0; j < tableBits; j++)
					CurvePointMath.twice(val, pOff, newTempOff);
			}
		}
	}
	
	public static final int MULTIPLY_TEMP_WORDS = 17 * POINT_WORDS + ADD_TEMP_WORDS;
	
	
	// Normalizes the coordinates of the given point. Idempotent operation.
	// Requires 72 words of temporary space. Constant-time with respect to the point.
	public static void normalize(int[] val, int pOff, int tempOff) {
		/* 
		 * Algorithm pseudocode:
		 * if (z != 0) {
		 *   x /= z
		 *   y /= z
		 *   z = 1
		 * } else {
		 *   x = x != 0 ? 1 : 0
		 *   y = y != 0 ? 1 : 0
		 *   z = 0
		 * }
		 */
		
		checkPoint(val, pOff);
		Int256Math.checkUint(val, tempOff);
		assert val.length - tempOff >= NORMALIZE_TEMP_WORDS;
		
		int nonzero = Int256Math.isZero(val, pOff + ZCOORD) ^ 1;
		int newTempOff = tempOff + POINT_WORDS;
		int normOff = tempOff;
		System.arraycopy(Int256Math.FIELD_MODULUS, 0, val, tempOff, NUM_WORDS);  // Reuses space
		Int256Math.reciprocal(val, pOff + ZCOORD, tempOff, normOff + ZCOORD, newTempOff);
		Int256Math.fieldMultiply(val, pOff + XCOORD, normOff + ZCOORD, normOff + XCOORD, newTempOff);
		Int256Math.fieldMultiply(val, pOff + YCOORD, normOff + ZCOORD, normOff + YCOORD, newTempOff);
		
		val[normOff + ZCOORD] = 1;
		Arrays.fill(val, normOff + ZCOORD + 1, normOff + ZCOORD + NUM_WORDS, 0);
		Int256Math.replace(val, pOff + XCOORD, normOff + ZCOORD, Int256Math.isZero(val, pOff + XCOORD) ^ 1);
		Int256Math.replace(val, pOff + YCOORD, normOff + ZCOORD, Int256Math.isZero(val, pOff + YCOORD) ^ 1);
		CurvePointMath.replace(val, pOff, normOff, nonzero);
	}
	
	public static final int NORMALIZE_TEMP_WORDS = POINT_WORDS + Int256Math.RECIPROCAL_TEMP_WORDS;
	
	
	/*---- Miscellaneous functions ----*/
	
	// Copies the point q into point p if enable is 1, or does nothing if enable is 0.
	// Constant-time with respect to both values and the enable.
	public static void replace(int[] val, int pOff, int qOff, int enable) {
		checkPoint(val, pOff);
		checkPoint(val, qOff);
		Int256Math.checkEnable(enable);
		
		int mask = -enable;
		for (int i = 0; i < POINT_WORDS; i++)
			val[pOff + i] = (val[qOff + i] & mask) | (val[pOff + i] & ~mask);
	}
	
	
	// Tests whether the given point is on the elliptic curve, returning 0 or 1.
	// The point needs to be normalized before the method is called. Zero is considered to be off the curve.
	// Requires 56 words of temporary space. Constant-time with respect to the point.
	public static int isOnCurve(int[] val, int pOff, int tempOff) {
		checkPoint(val, pOff);
		Int256Math.checkUint(val, tempOff);
		assert val.length - tempOff >= ISONCURVE_TEMP_WORDS;
		
		int rightOff   = tempOff + 0 * NUM_WORDS;
		int constOff   = tempOff + 1 * NUM_WORDS;
		int newTempOff = tempOff + 2 * NUM_WORDS;
		Int256Math.fieldSquare(val, pOff + XCOORD, rightOff, newTempOff);
		System.arraycopy(A, 0, val, constOff, NUM_WORDS);
		Int256Math.fieldAdd(val, rightOff, constOff, rightOff, newTempOff);
		Int256Math.fieldMultiply(val, rightOff, pOff + XCOORD, rightOff, newTempOff);
		System.arraycopy(B, 0, val, constOff, NUM_WORDS);
		Int256Math.fieldAdd(val, rightOff, constOff, rightOff, newTempOff);
		
		int leftOff = tempOff + 1 * NUM_WORDS;  // Reuses space
		Int256Math.fieldSquare(val, pOff + YCOORD, leftOff, newTempOff);
		return Int256Math.equalTo(val, leftOff, rightOff) & (isZero(val, pOff) ^ 1);
	}
	
	public static final int ISONCURVE_TEMP_WORDS = 2 * NUM_WORDS + Int256Math.FIELD_MULTIPLY_TEMP_WORDS;
	
	
	// Tests whether the given point is equal to the special zero point.
	// The point need not be normalized. Constant-time with respect to the point.
	public static int isZero(int[] val, int pOff) {
		// p.x == 0 && p.y != 0 && p.z == 0
		checkPoint(val, pOff);
		return Int256Math.isZero(val, pOff + XCOORD) & Int256Math.isZero(val, pOff + ZCOORD)
			& (Int256Math.isZero(val, pOff + YCOORD) ^ 1);
	}
	
	
	public static int[] getBasePoint() {
		return BASE_POINT.clone();
	}
	
	
	
	/*---- Helper functions ----*/
	
	private static void checkPoint(int[] arr, int off) {
		Int256Math.checkFieldInt(arr, off + XCOORD);
		Int256Math.checkFieldInt(arr, off + YCOORD);
		Int256Math.checkFieldInt(arr, off + ZCOORD);
	}
	
	
	/*---- Class constants ----*/
	
	// Sizes and offsets
	static final int XCOORD = 0 * NUM_WORDS;
	static final int YCOORD = 1 * NUM_WORDS;
	static final int ZCOORD = 2 * NUM_WORDS;
	
	// Curve parameters
	static final int[] A     = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
	static final int[] B     = {0x00000007, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
	static final int[] ORDER = {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
	
	// Elliptic curve points
	static final int[] ZERO_POINT = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // (0, 1, 0)
	static final int[] BASE_POINT = {
		0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E,
		0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77,
		0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
	
}
