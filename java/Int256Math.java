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
	
	
	/*---- Field arithmetic methods ----*/
	
	// Computes x = (x + y) mod prime. Constant-time with respect to both values.
	public static void fieldAdd(int[] x, int xOff, int[] y, int yOff) {
		checkFieldInt(x, xOff);
		checkFieldInt(y, yOff);
		checkOverlap(x, xOff, y, yOff);
		
		int c = uintAdd(x, xOff, y, yOff, 1);  // Perform addition
		assert((c >>> 1) == 0);
		uintSubtract(x, xOff, FIELD_MODULUS, 0, c | (lessThan(x, xOff, FIELD_MODULUS, 0) ^ 1));  // Conditionally subtract modulus
	}
	
	
	// Computes x = (x - y) mod prime. Constant-time with respect to both values.
	public static void fieldSubtract(int[] x, int xOff, int[] y, int yOff) {
		checkFieldInt(x, xOff);
		checkFieldInt(y, yOff);
		checkOverlap(x, xOff, y, yOff);
		
		int b = uintSubtract(x, xOff, y, yOff, 1);  // Perform subtraction
		assert((b >>> 1) == 0);
		uintAdd(x, xOff, FIELD_MODULUS, 0, b);  // Conditionally add modulus
	}
	
	
	// Computes x = (x * 2) mod prime. Constant-time with respect to the value.
	public static void fieldMultiply2(int[] x, int xOff) {
		checkFieldInt(x, xOff);
		int c = uintShiftLeft1(x, xOff);
		assert((c >>> 1) == 0);
		uintSubtract(x, xOff, FIELD_MODULUS, 0, c | (lessThan(x, xOff, FIELD_MODULUS, 0) ^ 1));  // Conditionally subtract modulus
	}
	
	
	// Computes x = (x * 3) mod prime. Requires 8 words of temporary space. Constant-time with respect to the value.
	public static void fieldMultiply3(int[] x, int xOff, int[] temp, int tempOff) {
		checkFieldInt(x, xOff);
		checkArray(temp, tempOff);
		System.arraycopy(x, xOff, temp, tempOff, NUM_WORDS);
		fieldMultiply2(x, xOff);
		fieldAdd(x, xOff, temp, tempOff);
	}
	
	
	// Computes x = x^2 mod prime. Requires 72 words of temporary space. Constant-time with respect to the value.
	public static void fieldSquare(int[] x, int xOff, int[] temp, int tempOff) {
		checkFieldInt(x, xOff);
		fieldMultiply(x, xOff, x, xOff, temp, tempOff);
	}
	
	
	// Computes x = (x * y) mod prime. Requires 72 words of temporary space. Constant-time with respect to both values.
	public static void fieldMultiply(int[] x, int xOff, int[] y, int yOff, int[] temp, int tempOff) {
		checkFieldInt(x, xOff);
		checkFieldInt(y, yOff);
		checkArray(temp, tempOff);
		assert temp.length - tempOff >= 9 * NUM_WORDS;
		
		// Compute raw product of this.value * other.value
		int product0Off = tempOff + 0 * NUM_WORDS;
		{
			long carry = 0;
			int i;
			for (i = 0; i < NUM_WORDS * 2 - 1; i++) {
				long sum = carry;
				int c = 0;
				if (i < NUM_WORDS) {
					for (int j = 0; j <= i; j++) {
						long prod = (x[xOff + j] & LONG_MASK) * (y[yOff + i - j] & LONG_MASK);
						sum += prod;
						c += lessThan(sum, prod);
					}
				} else {
					for (int j = NUM_WORDS - 1; j >= 0 && i - j < NUM_WORDS; j--) {
						long prod = (x[xOff + i - j] & LONG_MASK) * (y[yOff + j] & LONG_MASK);
						sum += prod;
						c += lessThan(sum, prod);
					}
				}
				assert(0 <= c && c <= NUM_WORDS);
				temp[product0Off + i] = (int)sum;
				carry = (long)c << 32 | sum >>> 32;
			}
			temp[product0Off + i] = (int)carry;
			assert((carry >>> 32) == 0);
		}
		
		// Barrett reduction algorithm begins here.
		// Multiply by floor(2^512 / MODULUS), which is 2^256 + 2^32 + 0x3D1
		int product1Off = tempOff + 2 * NUM_WORDS;
		{
			int carry = 0;
			for (int i = 0; i < NUM_WORDS * 3; i++) {
				long sum = carry;
				if (i < NUM_WORDS * 2)
					sum += (temp[product0Off + i] & LONG_MASK) * 0x3D1;
				if (i >= 1 && i < NUM_WORDS * 2 + 1)
					sum += temp[product0Off + i - 1] & LONG_MASK;
				if (i >= NUM_WORDS)
					sum += temp[product0Off + i - NUM_WORDS] & LONG_MASK;
				temp[product1Off + i] = (int)sum;
				carry = (int)(sum >>> 32);
				assert(0 <= carry && carry <= 0x3D3);
			}
			assert(carry == 0);
		}
		
		// Virtually shift right by 512 bits, then multiply by MODULUS. Note that MODULUS = 2^256 - 2^32 - 0x3D1
		int p1Shift = product1Off + NUM_WORDS * 2;
		int product2Off = tempOff + 5 * NUM_WORDS;
		{
			int borrow = 0;
			for (int i = 0; i < NUM_WORDS * 2; i++) {
				long diff = -borrow;
				if (i < NUM_WORDS)
					diff -= (temp[p1Shift + i] & LONG_MASK) * 0x3D1;
				if (i >= 1 && i < NUM_WORDS + 1)
					diff -= temp[p1Shift + i - 1] & LONG_MASK;
				if (i >= NUM_WORDS)
					diff += temp[p1Shift + i - NUM_WORDS] & LONG_MASK;
				temp[product2Off + i] = (int)diff;
				borrow = -(int)(diff >>> 32);
				assert(0 <= borrow && borrow <= 0x3D3);
			}
			assert(borrow == 0);
		}
		
		// Compute product0 - product2
		int differenceOff = tempOff + 7 * NUM_WORDS;  // We use 9 words but allocate 16
		{
			int borrow = 0;
			for (int i = 0; i < NUM_WORDS + 1; i++) {
				long diff = (temp[product0Off + i] & LONG_MASK) - (temp[product2Off + i] & LONG_MASK) - borrow;
				temp[differenceOff + i] = (int)diff;
				borrow = -(int)(diff >>> 32);
				assert((borrow >>> 1) == 0);
			}
		}
		
		// Final conditional subtraction
		System.arraycopy(temp, differenceOff, x, xOff, NUM_WORDS);
		int enable = (equalTo(temp[differenceOff + NUM_WORDS], 0) & lessThan(x, xOff, FIELD_MODULUS, 0)) ^ 1;
		uintSubtract(x, xOff, FIELD_MODULUS, 0, enable);
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
	
	// Returns 1 if x == y, otherwise 0.
	private static int equalTo(int x, int y) {
		int z = x ^ y;
		return ~(z | -z) >>> 31;
	}
	
	
	// Returns 1 if x < y, otherwise 0.
	private static int lessThan(long x, long y) {
		return (int)(((~x & y) | ((~x ^ y) & (x - y))) >>> 63);
	}
	
	
	private static void checkEnable(int en) {
		assert (en >>> 1) == 0;
	}
	
	private static void checkArray(int[] arr, int off) {
		assert off >= 0 && (off & 7) == 0 && arr.length - off >= NUM_WORDS;
	}
	
	private static void checkOverlap(int[] x, int xOff, int[] y, int yOff) {
		assert x != y || xOff != yOff;
	}
	
	private static void checkFieldInt(int[] arr, int off) {
		checkArray(arr, off);
		assert lessThan(arr, off, FIELD_MODULUS, 0) == 1;
	}
	
	
	/*---- Constants ----*/
	
	private static final int NUM_WORDS = 8;
	private static final long LONG_MASK = 0xFFFFFFFFL;
	
	private static final int[] ZERO = {0, 0, 0, 0, 0, 0, 0, 0};
	private static final int[] ONE  = {1, 0, 0, 0, 0, 0, 0, 0};
	private static final int[] FIELD_MODULUS = {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
	
}
