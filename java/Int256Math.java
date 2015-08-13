/* 
 * Performs arithmetic on unsigned 256-bit integers, which are represented as 8 consecutive ints.
 */
public final class Int256Math {
	
	/*---- Arithmetic methods ----*/
	
	// Computes x = (x + (y * enable)) mod 2^256, returning a carry-out of 0 or 1.
	// Enable must be 0 or 1. Constant-time with respect to both values and the enable.
	public static int uintAdd(int[] x, int xOff, int[] y, int yOff, int enable) {
		checkArray(x, xOff);
		checkArray(y, yOff);
		checkOverlap(x, xOff, y, yOff);
		checkEnable(enable);
		
		long mask = LONG_MASK & -enable;
		int carry = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			long sum = (x[xOff + i] & LONG_MASK) + (y[yOff + i] & mask) + carry;
			x[xOff + i] = (int)sum;
			carry = (int)(sum >>> 32);
			assert((carry >>> 1) == 0);
		}
		return carry;
	}
	
	
	// Computes x = (x - (y * enable)) mod 2^256, returning a borrow-out of 0 or 1.
	// Enable must be 0 or 1. Constant-time with respect to both values and the enable.
	public static int uintSubtract(int[] x, int xOff, int[] y, int yOff, int enable) {
		checkArray(x, xOff);
		checkArray(y, yOff);
		checkOverlap(x, xOff, y, yOff);
		checkEnable(enable);
		
		long mask = LONG_MASK & -enable;
		int borrow = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			long diff = (x[xOff + i] & LONG_MASK) - (y[yOff + i] & mask) - borrow;
			x[xOff + i] = (int)diff;
			borrow = -(int)(diff >>> 32);
			assert((borrow >>> 1) == 0);
		}
		return borrow;
	}
	
	
	// Computes x = (x << 1) mod 2^256, returning the old leftmost bit of 0 or 1.
	// Constant-time with respect to the value and the enable.
	public static int uintShiftLeft1(int[] x, int xOff) {
		checkArray(x, xOff);
		int prev = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			int cur = x[xOff + i];
			x[xOff + i] = cur << 1 | prev >>> 31;
			prev = cur;
		}
		return prev >>> 31;
	}
	
	
	// Computes x = (x >>> 1), which is the same as dividing by 2 and flooring.
	// Enable must be 0 or 1. Constant-time with respect to the value and the enable.
	public static void uintShiftRight1(int[] x, int xOff, int enable) {
		checkArray(x, xOff);
		checkEnable(enable);
		
		int mask = -enable;
		int cur = x[xOff];
		int i;
		for (i = 0; i < NUM_WORDS - 1; i++) {
			int next = x[xOff + i + 1];
			x[xOff + i] = ((cur >>> 1 | next << 31) & mask) | (cur & ~mask);
			cur = next;
		}
		x[xOff + i] = ((cur >>> 1) & mask) | (cur & ~mask);
	}
	
	
	// Computes x = x^-1 mod y. If x == 0, then the reciprocal is 0.
	// The modulus y must be odd and coprime to x. x must be less than the modulus.
	// Requires 40 words of temporary space. Constant-time with respect to both values.
	public static void reciprocal(int[] x, int xOff, int[] y, int yOff, int[] temp, int tempOff) {
		checkArray(x, xOff);
		checkArray(y, yOff);
		checkArray(temp, tempOff);
		assert temp.length - tempOff >= 5 * NUM_WORDS;
		if ((y[yOff] & 1) == 0)
			throw new IllegalArgumentException("Modulus must be odd");
		
		// Extended binary GCD algorithm
		int aOff = tempOff + 0 * NUM_WORDS;
		int bOff = tempOff + 1 * NUM_WORDS;
		int cOff = tempOff + 2 * NUM_WORDS;
		int dOff = tempOff + 3 * NUM_WORDS;
		int halfModOff = tempOff + 4 * NUM_WORDS;
		System.arraycopy(y, yOff, temp, aOff, NUM_WORDS);  // Must be odd
		System.arraycopy(x, xOff, temp, bOff, NUM_WORDS);  // Odd or even, and must be less than modulus
		System.arraycopy(ZERO, 0, temp, cOff, NUM_WORDS);
		System.arraycopy(ONE , 0, temp, dOff, NUM_WORDS);
		System.arraycopy(y, yOff, temp, halfModOff, NUM_WORDS);
		uintAdd(temp, halfModOff, ONE, 0, 1);
		uintShiftRight1(temp, halfModOff, 1);
		
		// Loop invariant: a = c*x mod y, and b = d*x mod y
		for (int i = 0; i < NUM_WORDS * 32 * 2; i++) {
			// Try to reduce a trailing zero of y. Pseudocode:
			// if (b % 2 == 0) {
			//     b /= 2;
			//     d = d % 2 == 0 ? d / 2 : y - (y - d) / 2;
			// }
			int yEven = ~temp[bOff] & 1;
			int bOdd = temp[dOff] & 1;
			uintShiftRight1(temp, bOff, yEven);
			uintShiftRight1(temp, dOff, yEven);
			uintAdd(temp, dOff, temp, halfModOff, yEven & bOdd);
			
			// If allowed, try to swap so that b >= a and then do b -= a. Pseudocode:
			// if (b % 2 != 0 && b != 1) {
			//     if (a > b) {
			//         a, b = b, a;
			//         c, d = d, c;
			//     }
			//     b -= a;
			//     d -= c;
			// }
			int enable = temp[bOff] & ~equalTo(temp, bOff, ONE, 0) & 1;
			int swap = enable & lessThan(temp, bOff, temp, aOff);
			swap(temp, aOff, temp, bOff, swap);
			uintSubtract(temp, bOff, temp, aOff, enable);
			swap(temp, cOff, temp, dOff, swap);
			int borrow = uintSubtract(temp, dOff, temp, cOff, enable);
			uintAdd(temp, dOff, y, yOff, borrow);
		}
		replace(x, xOff, temp, dOff, equalTo(x, xOff, ZERO, 0) ^ 1);
	}
	
	
	/*---- Miscellaneous methods ----*/
	
	// Copies the value y into x iff enable is 1.
	// Constant-time with respect to both values and the enable.
	public static void replace(int[] x, int xOff, int[] y, int yOff, int enable) {
		checkArray(x, xOff);
		checkArray(y, yOff);
		checkEnable(enable);
		
		int mask = -enable;
		for (int i = 0; i < NUM_WORDS; i++)
			x[xOff + i] = (y[yOff + i] & mask) | (x[xOff + i] & ~mask);
	}
	
	
	// Swaps the values x and y iff enable is 1.
	// Constant-time with respect to both values and the enable.
	public static void swap(int[] x, int xOff, int[] y, int yOff, int enable) {
		checkArray(x, xOff);
		checkArray(y, yOff);
		checkEnable(enable);
		
		int mask = -enable;
		for (int i = 0; i < NUM_WORDS; i++) {
			int a = x[xOff + i];
			int b = y[yOff + i];
			x[xOff + i] = (b & mask) | (a & ~mask);
			y[yOff + i] = (a & mask) | (b & ~mask);
		}
	}
	
	
	// Testing x == y and returns 0 or 1. Constant-time with respect to both values.
	public static int equalTo(int[] x, int xOff, int[] y, int yOff) {
		checkArray(x, xOff);
		checkArray(y, yOff);
		
		int diff = 0;
		for (int i = 0; i < NUM_WORDS; i++)
			diff |= x[xOff + i] ^ y[yOff + i];
		return ((diff | -diff) >> 31) + 1;
	}
	
	
	// Tests x < y and returns 0 or 1. Constant-time with respect to both values.
	public static int lessThan(int[] x, int xOff, int[] y, int yOff) {
		checkArray(x, xOff);
		checkArray(y, yOff);
		
		int result = 0;
		for (int i = 0; i < NUM_WORDS; i++) {
			int a = x[xOff + i];
			int b = y[yOff + i];
			int neq = a ^ b;
			neq = (neq | -neq) >>> 31;  // 0 or 1
			int lt = ((~a & b) | ((~a ^ b) & (a - b))) >>> 31;  // 0 or 1
			result = (~neq & result) | (neq & lt);
		}
		return result;
	}
	
	
	/*---- Helper methods ----*/
	
	private static void checkEnable(int en) {
		assert (en >>> 1) == 0;
	}
	
	private static void checkArray(int[] arr, int off) {
		assert off >= 0 && (off & 7) == 0 && arr.length - off >= NUM_WORDS;
	}
	
	private static void checkOverlap(int[] x, int xOff, int[] y, int yOff) {
		assert x != y || xOff != yOff;
	}
	
	
	/*---- Constants ----*/
	
	private static final int NUM_WORDS = 8;
	private static final long LONG_MASK = 0xFFFFFFFFL;
	
	private static final int[] ZERO = {0, 0, 0, 0, 0, 0, 0, 0};
	private static final int[] ONE  = {1, 0, 0, 0, 0, 0, 0, 0};
	
}
