import java.util.Arrays;


/* 
 * An unsigned 256-bit integer, represented as eight 32-bits words in little endian.
 * All arithmetic operations are performed modulo 2^256 (standard unsigned overflow behavior).
 * Instances of this class are mutable.
 * 
 * For example, the integer 0x0123456789abcdef000000001111111122222222333333334444444455555555 is represented by
 * the array {0x55555555, 0x44444444, 0x33333333, 0x22222222, 0x11111111, 0x00000000, 0x89abcdef, 0x01234567}.
 */
public class Uint256 implements Comparable<Uint256> {
	
	/* Fields */
	
	// The words representing this number in little endian, conceptually like this:
	// actualValue = value[0] << 0 | value[1] << 32 | ... | value[7] << 224.
	public final int[] value;
	
	
	
	/* Constructors */
	
	// Constructs a Uint256 initialized to zero. Constant-time.
	public Uint256() {
		value = new int[8];
	}
	
	
	// Constructs a Uint256 copying the given object. Constant-time.
	public Uint256(Uint256 other) {
		value = other.value.clone();
	}
	
	
	// Constructs a Uint256 from the given 64-character hexadecimal string. Not constant-time.
	public Uint256(String s) {
		this();
		if (s.length() != value.length * 8)
			throw new IllegalArgumentException();
		for (int i = 0; i < value.length; i++) {
			String temp = s.substring(i * 8, (i + 1) * 8);
			if (temp.charAt(0) == '+' || temp.charAt(0) == '-')
				throw new NumberFormatException();
			value[value.length - 1 - i] = (int)Long.parseLong(temp, 16);
		}
	}
	
	
	// Constructs a Uint256 from the given 32 bytes encoded in big-endian. Constant-time.
	public Uint256(byte[] b, int off) {
		this();
		if (off < 0 || b.length - off < value.length * 4)
			throw new ArrayIndexOutOfBoundsException();
		for (int i = 0; i < value.length * 4; i++)
			value[i >>> 2] |= (b[value.length * 4 - 1 - i] & 0xFF) << ((i & 3) << 3);
	}
	
	
	
	/* Arithmetic methods */
	
	// Adds the given number into this number, modulo 2^256. Constant-time with respect to both values.
	public void add(Uint256 other) {
		add(other, -1);
	}
	
	
	// Adds the given number into this number, modulo 2^256. The other number must be a distinct object.
	// Mask must be 0xFFFFFFFF to perform the operation or 0x00000000 to do nothing.
	// Returns the carry-out, which is 0 or 1. Constant-time with respect to both values.
	public int add(Uint256 other, int mask) {
		if (other == this || ((mask + 1) >>> 1) != 0)
			throw new IllegalArgumentException();
		long otherMask = LONG_MASK & mask;
		int carry = 0;
		for (int i = 0; i < value.length; i++) {
			long sum = (value[i] & LONG_MASK) + (other.value[i] & otherMask) + carry;
			value[i] = (int)sum;
			carry = (int)(sum >>> 32);
			assert((carry >>> 1) == 0);
		}
		return carry;
	}
	
	
	// Subtracts the given number from this number, modulo 2^256. Constant-time with respect to both values.
	public void subtract(Uint256 other) {
		subtract(other, -1);
	}
	
	
	// Subtracts the given number from this number, modulo 2^256. The other number must be a distinct object.
	// Mask must be 0xFFFFFFFF to perform the operation or 0x00000000 to do nothing.
	// Returns the borrow-out, which is 0 or 1. Constant-time with respect to both values.
	public int subtract(Uint256 other, int mask) {
		if (other == this || ((mask + 1) >>> 1) != 0)
			throw new IllegalArgumentException();
		long otherMask = LONG_MASK & mask;
		int borrow = 0;
		for (int i = 0; i < value.length; i++) {
			long diff = (value[i] & LONG_MASK) - (other.value[i] & otherMask) - borrow;
			value[i] = (int)diff;
			borrow = -(int)(diff >>> 32);
			assert((borrow >>> 1) == 0);
		}
		return borrow;
	}
	
	
	// Shifts this number left by 1 bit (same as multiplying by 2), modulo 2^256.
	// Returns the old leftmost bit, which is 0 or 1. Constant-time with respect to this value.
	public int shiftLeft1() {
		int prev = 0;
		for (int i = 0; i < value.length; i++) {
			int cur = value[i];
			value[i] = cur << 1 | prev >>> 31;
			prev = cur;
		}
		return prev >>> 31;
	}
	
	
	// Shifts this number right by 1 bit (same as dividing by 2 and flooring).
	// Constant-time with respect to this value.
	public void shiftRight1() {
		shiftRight1(-1);
	}
	
	
	// Shifts this number right by 1 bit (same as dividing by 2 and flooring).
	// Mask must be 0xFFFFFFFF to perform the operation or 0x00000000 to do nothing.
	// Constant-time with respect to this value.
	public void shiftRight1(int mask) {
		assert(((mask + 1) >>> 1) == 0);
		int cur = value[0];
		for (int i = 0; i < value.length - 1; i++) {
			int next = value[i + 1];
			value[i] = ((cur >>> 1 | next << 31) & mask) | (cur & ~mask);
			cur = next;
		}
		value[value.length - 1] = ((cur >>> 1) & mask) | (cur & ~mask);
	}
	
	
	// Computes the multiplicative inverse of this number with respect to the given modulus.
	// If this number is zero, the reciprocal is zero. Constant-time with respect to this value.
	// The modulus must be odd and coprime to this number. This number must be less than the modulus.
	public void reciprocal(Uint256 modulus) {
		// Extended binary GCD algorithm
		if (modulus == this || (modulus.value[0] & 1) == 0)
			throw new IllegalArgumentException();
		Uint256 x = new Uint256(modulus);  // Must be odd
		Uint256 y = new Uint256(this);  // Odd or even, and must be less than x
		Uint256 a = new Uint256(ZERO);
		Uint256 b = new Uint256(ONE);
		Uint256 halfModulus = new Uint256(modulus);
		halfModulus.add(ONE);
		halfModulus.shiftRight1();
		
		// Loop invariant: x = a*this mod modulus, and y = b*this mod modulus
		for (int i = 0; i < value.length * 32 * 2; i++) {
			// Try to reduce a trailing zero of y. Pseudocode:
			// if (y % 2 == 0) {
			//     y /= 2;
			//     b = b % 2 == 0 ? b / 2 : modulus - (modulus - b) / 2;
			// }
			int yEven = (y.value[0] & 1) - 1;
			int bOdd = -(b.value[0] & 1);
			y.shiftRight1(yEven);
			b.shiftRight1(yEven);
			b.add(halfModulus, yEven & bOdd);
			
			// If allowed, try to swap so that y >= x and then do y -= x. Pseudocode:
			// if (y % 2 != 0 && y != 1) {
			//     if (x > y) {
			//         x, y = y, x;
			//         a, b = b, a;
			//     }
			//     y -= x;
			//     b -= a;
			// }
			int enable = (-(y.value[0] & 1)) & ~y.equalTo(ONE);
			int swap = enable & y.lessThan(x);
			x.swap(y, swap);
			y.subtract(x, enable);
			a.swap(b, swap);
			int borrow = b.subtract(a, enable);
			b.add(modulus, -borrow);
		}
		replace(b, ~this.equalTo(ZERO));
	}
	
	
	/* Miscellaneous methods */
	
	// Copies the given value into this number if mask is 0xFFFFFFFF, or
	// does nothing if mask is 0x00000000. Constant-time with respect to both values.
	public void replace(Uint256 other, int mask) {
		assert(((mask + 1) >>> 1) == 0);
		for (int i = 0; i < value.length; i++)
			value[i] = (other.value[i] & mask) | (value[i] & ~mask);
	}
	
	
	// Swaps the value of this number with the given number if mask is 0xFFFFFFFF,
	// or does nothing if mask is 0x00000000. Constant-time with respect to both values.
	public void swap(Uint256 other, int mask) {
		assert(((mask + 1) >>> 1) == 0);
		for (int i = 0; i < value.length; i++) {
			int x = this .value[i];
			int y = other.value[i];
			this .value[i] = (y & mask) | (x & ~mask);
			other.value[i] = (x & mask) | (y & ~mask);
		}
	}
	
	
	// Returns this number as a 64-digit hexadecimal string in lowercase. Not constant-time.
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (int i = value.length - 1; i >= 0; i--)
			sb.append(String.format("%08x", value[i]));
		return sb.toString();
	}
	
	
	// Returns the hash code of this number in a way consistent with equals(). Constant-time with respect to this value.
	public int hashCode() {
		int result = 0;
		for (int x : value)
			result = Integer.rotateLeft(result, 7) + x;
		return result;
	}
	
	
	// Tests whether the given object is a Uint256 with the same value. Not constant-time.
	public boolean equals(Object obj) {
		return obj == this || obj instanceof Uint256 && Arrays.equals(value, ((Uint256)obj).value);
	}
	
	
	// Returns whether this number is less than, equal to, or greater than the given number. Not constant-time.
	public int compareTo(Uint256 other) {
		for (int i = value.length - 1; i >= 0; i--) {
			int cmp = Integer.compareUnsigned(value[i], other.value[i]);
			if (cmp != 0)
				return cmp;
		}
		return 0;
	}
	
	
	// Returns 0x00000000 or 0xFFFFFFFF depending on whether this value
	// is equal to the given one. Constant-time with respect to both values.
	public int equalTo(Uint256 other) {
		int diff = 0;
		for (int i = 0; i < value.length; i++)
			diff |= value[i] ^ other.value[i];
		return ~((diff | -diff) >> 31);
	}
	
	
	// Returns 0x00000000 or 0xFFFFFFFF depending on whether this value
	// is less than the given one. Constant-time with respect to both values.
	public int lessThan(Uint256 other) {
		int result = 0;
		for (int i = 0; i < value.length; i++) {
			int x = this .value[i];
			int y = other.value[i];
			int neq = x ^ y;
			neq = (neq | -neq) >> 31;  // 0x00000000 or 0xFFFFFFFF
			int lt = ((~x & y) | ((~x ^ y) & (x - y))) >> 31;  // 0x00000000 or 0xFFFFFFFF
			result = (~neq & result) | (neq & lt);
		}
		return result;
	}
	
	
	public byte[] toBigEndianBytes() {
		byte[] result = new byte[value.length * 4];
		for (int i = 0; i < result.length; i++)
			result[result.length - 1 - i] = (byte)(value[i >>> 2] >>> ((i & 3) << 3));
		return result;
	}
	
	
	
	/* Constants */
	
	public static final Uint256 ZERO = new Uint256();
	public static final Uint256 ONE = new Uint256("0000000000000000000000000000000000000000000000000000000000000001");
	
	protected static final long LONG_MASK = 0xFFFFFFFFL;
	
}
