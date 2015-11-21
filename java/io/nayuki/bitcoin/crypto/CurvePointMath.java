/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * http://www.nayuki.io/page/bitcoin-cryptography-library
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
	
	/*---- Arithmetic functions ----*/
	
	// Doubles the given curve point. Requires 72 words of temporary space.
	// The resulting point is usually not normalized. Constant-time with respect to the point.
	public static void twice(int[] val, int pOff, int tempOff) {
		/* 
		 * (Derived from http://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates)
		 * if (p == ZERO || p.y == 0)
		 *   p = ZERO
		 * else {
		 *   a = 0 (curve parameter)
		 *   s = 2 * p.y * p.z
		 *   t = 2 * p.x * p.y * s
		 *   u = 3 * p.x^2 + a * p.z^2
		 *   v = u^2 - 2 * t
		 *   p.x = s * v
		 *   p.y = u * (t - v) - 2 * (p.y * s)^2
		 *   p.z = s^3
		 * }
		 */
		
		checkPoint(val, pOff);
		Int256Math.checkUint(val, tempOff);
		assert val.length - tempOff >= 9 * NUM_WORDS;
		
		int zeroResult = CurvePointMath.isZero(val, pOff) | Int256Math.isZero(val, pOff + YCOORD);
		int newTempOff = tempOff + 4 * NUM_WORDS;
		
		int sOff = tempOff + 0 * NUM_WORDS;
		Int256Math.fieldMultiply(val, pOff + YCOORD, pOff + ZCOORD, sOff, newTempOff);
		Int256Math.fieldMultiply2(val, sOff, sOff, newTempOff);
		
		int tOff = tempOff + 1 * NUM_WORDS;
		Int256Math.fieldMultiply2(val, sOff, tOff, newTempOff);
		Int256Math.fieldMultiply(val, tOff, pOff + XCOORD, tOff, newTempOff);
		Int256Math.fieldMultiply(val, tOff, pOff + YCOORD, tOff, newTempOff);
		
		int uOff = tempOff + 2 * NUM_WORDS;
		int vOff = tempOff + 3 * NUM_WORDS;
		Int256Math.fieldSquare(val, pOff + XCOORD, uOff, newTempOff);
		Int256Math.fieldMultiply2(val, uOff, vOff, newTempOff);
		Int256Math.fieldAdd(val, uOff, vOff, uOff, newTempOff);
		Int256Math.fieldSquare(val, uOff, vOff, newTempOff);
		Int256Math.fieldSubtract(val, vOff, tOff, vOff, newTempOff);
		Int256Math.fieldSubtract(val, vOff, tOff, vOff, newTempOff);
		
		// Set x and y
		Int256Math.fieldMultiply(val, sOff, vOff, pOff + XCOORD, newTempOff);
		Int256Math.fieldSquare(val, sOff, pOff + ZCOORD, newTempOff);
		Int256Math.fieldMultiply(val, pOff + ZCOORD, sOff, pOff + ZCOORD, newTempOff);
		
		// Set z
		Int256Math.fieldMultiply(val, pOff + YCOORD, sOff, pOff + YCOORD, newTempOff);
		Int256Math.fieldSquare(val, pOff + YCOORD, pOff + YCOORD, newTempOff);
		Int256Math.fieldMultiply2(val, pOff + YCOORD, pOff + YCOORD, newTempOff);
		Int256Math.fieldSubtract(val, tOff, vOff, tOff, newTempOff);
		Int256Math.fieldMultiply(val, uOff, tOff, uOff, newTempOff);
		Int256Math.fieldSubtract(val, uOff, pOff + YCOORD, pOff + YCOORD, newTempOff);
		
		System.arraycopy(ZERO_POINT, 0, val, tempOff, POINT_WORDS);  // Reuses space
		CurvePointMath.replace(val, pOff, tempOff, zeroResult);
	}
	
	
	// Adds the point q into point p. Requires 144 words of temporary space.
	// The resulting state is usually not normalized. Constant-time with respect to both points.
	public static void add(int[] val, int pOff, int qOff, int tempOff) {
		/* 
		 * (Derived from http://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates)
		 * if (p == ZERO)
		 *   p = q
		 * else if (q == ZERO)
		 *   p = p
		 * else {
		 *   u0 = p.x * q.z
		 *   u1 = q.x * p.z
		 *   v0 = p.y * q.z
		 *   v1 = q.y * p.z
		 *   if (v0 == v1)  // Same y coordinates
		 *     p = (u0 != u1) ? ZERO : twice(p)
		 *   else {
		 *     u = u0 - u1
		 *     v = v0 - v1
		 *     w = p.z * q.z
		 *     t = w * v^2 - (u0 + u1) * u^2
		 *     p.x = u * t
		 *     p.y = v * (u0 * u^2 - t) - v0 * u^3
		 *     p.z = u^3 * w
		 *   }
		 * }
		 */
		
		checkPoint(val, pOff);
		checkPoint(val, qOff);
		Int256Math.checkUint(val, tempOff);
		assert val.length - tempOff >= 18 * NUM_WORDS;
		
		int pIsZero = CurvePointMath.isZero(val, pOff);
		int qIsZero = CurvePointMath.isZero(val, qOff);
		CurvePointMath.replace(val, pOff, qOff, pIsZero);
		
		int twicedOff = tempOff + 0 * NUM_WORDS;
		System.arraycopy(val, pOff, val, twicedOff, NUM_WORDS);
		CurvePointMath.twice(val, twicedOff, tempOff + POINT_WORDS);
		
		int newTempOff = tempOff + 13 * NUM_WORDS;
		int u0Off = tempOff + 3 * NUM_WORDS;
		int u1Off = tempOff + 4 * NUM_WORDS;
		int v0Off = tempOff + 5 * NUM_WORDS;
		int v1Off = tempOff + 6 * NUM_WORDS;
		Int256Math.fieldMultiply(val, pOff + XCOORD, qOff + ZCOORD, u0Off, newTempOff);
		Int256Math.fieldMultiply(val, qOff + XCOORD, pOff + ZCOORD, u1Off, newTempOff);
		Int256Math.fieldMultiply(val, pOff + YCOORD, qOff + ZCOORD, v0Off, newTempOff);
		Int256Math.fieldMultiply(val, qOff + YCOORD, pOff + ZCOORD, v1Off, newTempOff);
		
		int sameX = Int256Math.equalTo(val, u0Off, u1Off);
		int sameY = Int256Math.equalTo(val, v0Off, v1Off);
		
		int uOff = tempOff + 7 * NUM_WORDS;
		int vOff = tempOff + 8 * NUM_WORDS;
		int wOff = tempOff + 9 * NUM_WORDS;
		Int256Math.fieldSubtract(val, u0Off, u1Off, uOff, newTempOff);
		Int256Math.fieldSubtract(val, v0Off, v1Off, vOff, newTempOff);
		Int256Math.fieldMultiply(val, pOff + ZCOORD, qOff + ZCOORD, wOff, newTempOff);
		
		int u2Off = tempOff + 10 * NUM_WORDS;
		int u3Off = tempOff + 11 * NUM_WORDS;
		Int256Math.fieldSquare(val, uOff, u2Off, newTempOff);
		Int256Math.fieldMultiply(val, uOff, u2Off, u3Off, newTempOff);
		
		Int256Math.fieldAdd(val, u0Off, u1Off, u1Off, newTempOff);
		Int256Math.fieldMultiply(val, u1Off, u2Off, u1Off, newTempOff);
		int tOff = tempOff + 12 * NUM_WORDS;
		Int256Math.fieldSquare(val, vOff, tOff, newTempOff);
		Int256Math.fieldMultiply(val, wOff, tOff, tOff, newTempOff);
		Int256Math.fieldSubtract(val, tOff, u1Off, tOff, newTempOff);
		
		int assign = (pIsZero | qIsZero | sameY) ^ 1;
		Int256Math.fieldMultiply(val, uOff, tOff, uOff, newTempOff);
		Int256Math.replace(val, pOff + XCOORD, uOff, assign);
		Int256Math.fieldMultiply(val, wOff, u3Off, wOff, newTempOff);
		Int256Math.replace(val, pOff + ZCOORD, wOff, assign);
		Int256Math.fieldMultiply(val, u0Off, u2Off, u0Off, newTempOff);
		Int256Math.fieldSubtract(val, u0Off, tOff, tOff, newTempOff);
		Int256Math.fieldMultiply(val, tOff, vOff, tOff, newTempOff);
		Int256Math.fieldMultiply(val, v0Off, u3Off, v0Off, newTempOff);
		Int256Math.fieldSubtract(val, tOff, v0Off, tOff, newTempOff);
		Int256Math.replace(val, pOff + YCOORD, tOff, assign);
		
		int cond = (pIsZero ^ 1) & (qIsZero ^ 1) & sameY;
		int zeroPointOff = twicedOff + POINT_WORDS;
		System.arraycopy(ZERO_POINT, 0, val, zeroPointOff, POINT_WORDS);  // Reuses space
		CurvePointMath.replace(val, pOff, zeroPointOff, cond & (sameX ^ 1));
		CurvePointMath.replace(val, pOff, twicedOff, cond & sameX);
	}
	
	
	// Multiplies the given point by the given unsigned integer. Requires 552 words of temporary space.
	// The resulting state is usually not normalized. Constant-time with respect to both values.
	public static void multiply(int[] val, int pOff, int nOff, int tempOff) {
		checkPoint(val, pOff);
		Int256Math.checkUint(val, nOff);
		Int256Math.checkUint(val, tempOff);
		assert val.length - tempOff >= 69 * NUM_WORDS;
		
		// Precompute [p*0, p*1, ..., p*15]
		int newTempOff = tempOff + 51 * NUM_WORDS;
		int tableOff = tempOff;  // Uses 16 * POINT_WORDS elements
		System.arraycopy(ZERO_POINT, 0, val, tableOff, POINT_WORDS);
		System.arraycopy(val, pOff, val, tableOff + 1 * POINT_WORDS, POINT_WORDS);
		System.arraycopy(val, pOff, val, tableOff + 2 * POINT_WORDS, POINT_WORDS);
		CurvePointMath.twice(val, tableOff + 2 * POINT_WORDS, newTempOff);
		for (int i = 3; i < 16; i++) {
			System.arraycopy(val, tableOff + (i - 1) * POINT_WORDS, val, tableOff + i * POINT_WORDS, POINT_WORDS);
			CurvePointMath.add(val, tableOff + i * POINT_WORDS, pOff, newTempOff);
		}
		
		// Process 4 bits per iteration (windowed method)
		System.arraycopy(ZERO_POINT, 0, val, pOff, POINT_WORDS);
		int qOff = tempOff + 16 * POINT_WORDS;
		for (int i = 256 - 4; i >= 0; i -= 4) {
			if (i != 256 - 4) {
				for (int j = 0; j < 4; j++)
					CurvePointMath.twice(val, pOff, newTempOff);
			}
			int inc = (val[nOff + (i >>> 5)] >>> (i & 31)) & 15;
			for (int j = 0; j < 16; j++)
				CurvePointMath.replace(val, qOff, tableOff + j * POINT_WORDS, Int256Math.equalTo(j, inc));
			CurvePointMath.add(val, pOff, qOff, newTempOff);
		}
	}
	
	
	// Normalizes the coordinates of the given point. If z != 0, then (x', y', z') = (x/z, y/z, 1);
	// otherwise special logic occurs. Requires 72 words of temporary space. Constant-time with respect to the point.
	public static void normalize(int[] val, int pOff, int tempOff) {
		/* 
		 * if (z != 0) {
		 *   x /= z;
		 *   y /= z;
		 *   z = 1;
		 * } else {
		 *   x = x != 0 ? 1 : 0;
		 *   y = y != 0 ? 1 : 0;
		 *   z = 0;
		 * }
		 */
		
		checkPoint(val, pOff);
		Int256Math.checkUint(val, tempOff);
		assert val.length - tempOff >= 9 * NUM_WORDS;
		
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
	
	
	/*---- Miscellaneous functions ----*/
	
	// Copies the point q into p iff enable is 1.
	// Constant-time with respect to both values and the enable.
	public static void replace(int[] val, int pOff, int qOff, int enable) {
		checkPoint(val, pOff);
		checkPoint(val, qOff);
		Int256Math.checkEnable(enable);
		
		int mask = -enable;
		for (int i = 0; i < POINT_WORDS; i++)
			val[pOff + i] = (val[qOff + i] & mask) | (val[pOff + i] & ~mask);
	}
	
	
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
	static final int POINT_WORDS = 3 * NUM_WORDS;
	static final int XCOORD = 0 * NUM_WORDS;
	static final int YCOORD = 1 * NUM_WORDS;
	static final int ZCOORD = 2 * NUM_WORDS;
	
	// Curve parameters
	static final int[] ORDER = {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
	
	// Elliptic curve points
	static final int[] ZERO_POINT = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // (0, 1, 0)
	static final int[] BASE_POINT = {
		0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E,
		0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77,
		0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
	
}
