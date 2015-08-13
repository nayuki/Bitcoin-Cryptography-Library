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
