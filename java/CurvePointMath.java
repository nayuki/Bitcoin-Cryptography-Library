/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */


/* 
 * Performs arithmetic on elliptic curve points, which are represented as 24 consecutive ints.
 */
public final class CurvePointMath {
	
	/*---- Arithmetic functions ----*/
	
	// Doubles the given curve point. Requires 120 words of temporary space.
	// The resulting point is usually not normalized. Constant-time with respect to the point.
	public static void twice(int[] p, int pOff, int[] temp, int tempOff) {
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
		
		int zeroResult = isZero(p, pOff) | Int256Math.equalTo(p, pOff + XCOORD, ZERO, 0);
		int newTempOff = tempOff + 6 * NUM_WORDS;
		
		int sOff = tempOff + 0 * NUM_WORDS;
		System.arraycopy(p, pOff + ZCOORD, temp, sOff, NUM_WORDS);
		Int256Math.fieldMultiply(temp, sOff, p, pOff + YCOORD, temp, newTempOff);
		Int256Math.fieldMultiply2(temp, sOff);
		
		int tOff = tempOff + 1 * NUM_WORDS;
		System.arraycopy(temp, sOff, temp, tOff, NUM_WORDS);
		Int256Math.fieldMultiply(temp, tOff, p, pOff + YCOORD, temp, newTempOff);
		Int256Math.fieldMultiply(temp, tOff, p, pOff + XCOORD, temp, newTempOff);
		Int256Math.fieldMultiply2(temp, tOff);
		
		int t2Off = tempOff + 2 * NUM_WORDS;
		System.arraycopy(temp, tOff, temp, t2Off, NUM_WORDS);
		Int256Math.fieldMultiply2(temp, t2Off);
		
		int uOff = tempOff + 3 * NUM_WORDS;
		System.arraycopy(p, pOff + XCOORD, temp, uOff, NUM_WORDS);
		Int256Math.fieldSquare(temp, uOff, temp, newTempOff);
		Int256Math.fieldMultiply3(temp, uOff, temp, newTempOff);
		
		int vOff = tempOff + 4 * NUM_WORDS;
		System.arraycopy(temp, uOff, temp, vOff, NUM_WORDS);
		Int256Math.fieldSquare(temp, vOff, temp, newTempOff);
		Int256Math.fieldSubtract(temp, vOff, temp, t2Off);
		
		Int256Math.replace(p, pOff + XCOORD, temp, vOff, 1);
		Int256Math.fieldMultiply(p, pOff + XCOORD, temp, sOff, temp, newTempOff);
		
		int s2Off = tempOff + 5 * NUM_WORDS;
		System.arraycopy(temp, sOff, temp, s2Off, NUM_WORDS);
		Int256Math.fieldSquare(temp, s2Off, temp, newTempOff);
		
		Int256Math.replace(p, pOff + ZCOORD, temp, s2Off, 1);
		Int256Math.fieldMultiply(p, pOff + ZCOORD, temp, sOff, temp, newTempOff);
		
		Int256Math.fieldSquare(p, pOff + YCOORD, temp, newTempOff);
		Int256Math.fieldMultiply(temp, s2Off, p, pOff + YCOORD, temp, newTempOff);
		Int256Math.fieldMultiply2(temp, s2Off);
		Int256Math.fieldSubtract(temp, tOff, temp, vOff);
		Int256Math.fieldMultiply(temp, uOff, temp, tOff, temp, newTempOff);
		Int256Math.fieldSubtract(temp, uOff, temp, s2Off);
		Int256Math.replace(p, pOff + YCOORD, temp, uOff, 1);
		
		CurvePointMath.replace(p, pOff, ZERO_POINT, 0, zeroResult);
	}
	
	
	// Adds the point q into point p. Requires 224 words of temporary space.
	// The resulting state is usually not normalized. Constant-time with respect to both points.
	public static void add(int[] p, int pOff, int[] q, int qOff, int[] temp, int tempOff) {
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
		
		int pIsZero = isZero(p, pOff);
		int qIsZero = isZero(q, qOff);
		CurvePointMath.replace(p, pOff, q, qOff, pIsZero);
		int newTempOff = tempOff + 13 * NUM_WORDS;
		
		int u0Off = tempOff + 0 * NUM_WORDS;
		int u1Off = tempOff + 1 * NUM_WORDS;
		int v0Off = tempOff + 2 * NUM_WORDS;
		int v1Off = tempOff + 3 * NUM_WORDS;
		System.arraycopy(p, pOff + XCOORD, temp, u0Off, NUM_WORDS);
		System.arraycopy(q, qOff + XCOORD, temp, u1Off, NUM_WORDS);
		System.arraycopy(p, pOff + YCOORD, temp, v0Off, NUM_WORDS);
		System.arraycopy(q, qOff + YCOORD, temp, v1Off, NUM_WORDS);
		Int256Math.fieldMultiply(temp, u0Off, q, qOff + ZCOORD, temp, newTempOff);
		Int256Math.fieldMultiply(temp, u1Off, p, pOff + ZCOORD, temp, newTempOff);
		Int256Math.fieldMultiply(temp, v0Off, q, qOff + ZCOORD, temp, newTempOff);
		Int256Math.fieldMultiply(temp, v1Off, p, pOff + ZCOORD, temp, newTempOff);
		
		int sameX = Int256Math.equalTo(temp, u0Off, temp, u1Off);
		int sameY = Int256Math.equalTo(temp, v0Off, temp, v1Off);
		int twicedOff = tempOff + 4 * NUM_WORDS;
		System.arraycopy(p, pOff, temp, twicedOff, NUM_WORDS);
		CurvePointMath.twice(temp, twicedOff, temp, newTempOff);
		
		int uOff = tempOff + 7 * NUM_WORDS;
		int vOff = tempOff + 8 * NUM_WORDS;
		int wOff = tempOff + 9 * NUM_WORDS;
		System.arraycopy(temp, u0Off, temp, uOff, NUM_WORDS);
		System.arraycopy(temp, v0Off, temp, vOff, NUM_WORDS);
		System.arraycopy(p, pOff + ZCOORD, temp, wOff, NUM_WORDS);
		Int256Math.fieldSubtract(temp, uOff, temp, u1Off);
		Int256Math.fieldSubtract(temp, vOff, temp, v1Off);
		Int256Math.fieldMultiply(temp, wOff, q, qOff + ZCOORD, temp, newTempOff);
		
		int u2Off = tempOff + 10 * NUM_WORDS;
		int u3Off = tempOff + 11 * NUM_WORDS;
		System.arraycopy(temp, uOff, temp, u2Off, NUM_WORDS);
		Int256Math.fieldSquare(temp, u2Off, temp, newTempOff);
		System.arraycopy(temp, u2Off, temp, u3Off, NUM_WORDS);
		Int256Math.fieldMultiply(temp, u3Off, temp, uOff, temp, newTempOff);
		
		Int256Math.fieldAdd(temp, u1Off, temp, u0Off);
		Int256Math.fieldMultiply(temp, u1Off, temp, u2Off, temp, newTempOff);
		int tOff = tempOff + 12 * NUM_WORDS;
		System.arraycopy(temp, vOff, temp, tOff, NUM_WORDS);
		Int256Math.fieldSquare(temp, tOff, temp, newTempOff);
		Int256Math.fieldMultiply(temp, tOff, temp, wOff, temp, newTempOff);
		Int256Math.fieldSubtract(temp, tOff, temp, u1Off);
		
		int assign = (pIsZero | qIsZero | sameY) ^ 1;
		Int256Math.fieldMultiply(temp, uOff, temp, tOff, temp, newTempOff);
		Int256Math.replace(p, pOff + XCOORD, temp, uOff, assign);
		Int256Math.fieldMultiply(temp, wOff, temp, u3Off, temp, newTempOff);
		Int256Math.replace(p, pOff + ZCOORD, temp, wOff, assign);
		Int256Math.fieldMultiply(temp, u0Off, temp, u2Off, temp, newTempOff);
		Int256Math.fieldSubtract(temp, u0Off, temp, tOff);
		Int256Math.fieldMultiply(temp, u0Off, temp, vOff, temp, newTempOff);
		Int256Math.fieldMultiply(temp, v0Off, temp, u3Off, temp, newTempOff);
		Int256Math.fieldSubtract(temp, u0Off, temp, v0Off);
		Int256Math.replace(p, pOff + YCOORD, temp, u0Off, assign);
		
		int cond = (pIsZero ^ 1) & (qIsZero ^ 1) & sameY;
		CurvePointMath.replace(p, pOff, ZERO_POINT, 0, cond & (sameX ^ 1));
		CurvePointMath.replace(p, pOff, temp, twicedOff, cond & sameX);
	}
	
	
	// Multiplies the given point by the given unsigned integer. Requires 632 words of temporary space.
	// The resulting state is usually not normalized. Constant-time with respect to both values.
	public static void multiply(int[] p, int pOff, int[] n, int nOff, int[] temp, int tempOff) {
		// Precompute [p*0, p*1, ..., p*15]
		int newTempOff = tempOff + 51 * NUM_WORDS;
		int tableOff = tempOff;  // Uses 16 * 3 * NUM_WORDS elements
		System.arraycopy(ZERO_POINT, 0, temp, tableOff, 3 * NUM_WORDS);
		System.arraycopy(p, pOff, temp, tableOff + 3 * NUM_WORDS, 3 * NUM_WORDS);
		System.arraycopy(p, pOff, temp, tableOff + 6 * NUM_WORDS, 3 * NUM_WORDS);
		CurvePointMath.twice(temp, tableOff + 6 * NUM_WORDS, temp, newTempOff);
		for (int i = 3; i < 16; i++) {
			System.arraycopy(temp, tableOff + (i - 1) * 3 * NUM_WORDS, temp, tableOff + i * 3 * NUM_WORDS, 3 * NUM_WORDS);
			CurvePointMath.add(temp, tableOff + i * 3 * NUM_WORDS, p, pOff, temp, newTempOff);
		}
		
		// Process 4 bits per iteration (windowed method)
		System.arraycopy(ZERO_POINT, 0, p, pOff, 3 * NUM_WORDS);
		int qOff = tempOff + 16 * 3 * NUM_WORDS;
		for (int i = 256 - 4; i >= 0; i -= 4) {
			if (i != 256 - 4) {
				for (int j = 0; j < 4; j++)
					CurvePointMath.twice(p, pOff, temp, newTempOff);
			}
			int inc = (n[nOff + (i >>> 5)] >>> (i & 31)) & 15;
			for (int j = 0; j < 16; j++)
				CurvePointMath.replace(temp, qOff, temp, tableOff + j * 3 * NUM_WORDS, Int256Math.equalTo(j, inc));
			CurvePointMath.add(p, pOff, temp, qOff, temp, newTempOff);
		}
	}
	
	
	// Normalizes the coordinates of the given point. If z != 0, then (x', y', z') = (x/z, y/z, 1);
	// otherwise special logic occurs. Requires 96 words of temporary space. Constant-time with respect to the point.
	public static void normalize(int[] p, int pOff, int[] temp, int tempOff) {
		int nonzero = Int256Math.equalTo(p, pOff + ZCOORD, ZERO, 0) ^ 1;
		int newTempOff = tempOff + 24;
		int normOff = tempOff;
		System.arraycopy(p, pOff, temp, normOff, 3 * NUM_WORDS);
		Int256Math.reciprocal(temp, normOff + ZCOORD, FIELD_MODULUS, 0, temp, newTempOff);
		Int256Math.fieldMultiply(temp, normOff + XCOORD, temp, normOff + ZCOORD, temp, newTempOff);
		Int256Math.fieldMultiply(temp, normOff + YCOORD, temp, normOff + ZCOORD, temp, newTempOff);
		Int256Math.replace(temp, normOff + ZCOORD, ONE, 0, 1);
		Int256Math.replace(p, pOff + XCOORD, ONE, 0, Int256Math.equalTo(p, pOff + XCOORD, ZERO, 0) ^ 1);
		Int256Math.replace(p, pOff + YCOORD, ONE, 0, Int256Math.equalTo(p, pOff + YCOORD, ZERO, 0) ^ 1);
		CurvePointMath.replace(p, pOff, temp, normOff, nonzero);
	}
	
	
	/*---- Miscellaneous functions ----*/
	
	// Copies the point q into p iff enable is 1.
	// Constant-time with respect to both values and the enable.
	public static void replace(int[] p, int pOff, int[] q, int qOff, int enable) {
		int mask = -enable;
		for (int i = 0; i < 3 * NUM_WORDS; i++)
			p[pOff + i] = (q[qOff + i] & mask) | (p[pOff + i] & ~mask);
	}
	
	
	// Tests whether the given point is equal to the special zero point.
	// The point need not be normalized. Constant-time with respect to the point.
	public static int isZero(int[] p, int pOff) {
		// p.x == 0 && p.y != 0 && p.z == 0
		return
			 Int256Math.equalTo(p, pOff + XCOORD, ZERO, 0) &
			(Int256Math.equalTo(p, pOff + YCOORD, ZERO, 0) ^ 1) &
			 Int256Math.equalTo(p, pOff + ZCOORD, ZERO, 0);
	}
	
	
	public static int[] getBasePoint() {
		return BASE_POINT.clone();
	}
	
	
	/*---- Constants ----*/
	
	// Sizes and offsets
	private static final int NUM_WORDS = 8;
	private static final int XCOORD = 0 * NUM_WORDS;
	private static final int YCOORD = 1 * NUM_WORDS;
	private static final int ZCOORD = 2 * NUM_WORDS;
	
	// Unsigned 256-bit integers
	private static final int[] ZERO = {0, 0, 0, 0, 0, 0, 0, 0};
	private static final int[] ONE  = {1, 0, 0, 0, 0, 0, 0, 0};
	private static final int[] FIELD_MODULUS = {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
	
	// Elliptic curve points
	private static final int[] ZERO_POINT = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	private static final int[] BASE_POINT = {
		0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E,
		0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77,
		0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
	
}
