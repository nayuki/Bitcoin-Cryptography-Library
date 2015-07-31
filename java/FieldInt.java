/* 
 * An unsigned 256-bit integer modulo a specific prime number, for Bitcoin and secp256k1.
 * The input and output values of each method are always in the range [0, MODULUS).
 * Instances of this class are mutable.
 * 
 * Some behaviors are specific to FieldInt (such as reciprocal), while others are
 * the same as Uint256 (such as comparisons). The number representation format is
 * the same as Uint256. It is illegal to set the value to be greater than or equal
 * to MODULUS; undefined behavior will result.
 */
public final class FieldInt extends AbstractInt256 implements Comparable<FieldInt> {
	
	/* Constructors */
	
	public FieldInt(String s) {
		super(s);
	}
	
	
	public FieldInt(FieldInt other) {
		super(other);
	}
	
	
	public FieldInt(byte[] b, int off) {
		super(b, off);
	}
	
	
	
	/* Arithmetic methods */
	
	// Adds the given number into this number, modulo the prime. Constant-time with respect to both values.
	public void add(FieldInt other) {
		int c = super.add(other, -1);  // Perform addition
		super.subtract(MODULUS, -c | ~this.lessThan(MODULUS));  // Conditionally subtract modulus
	}
	
	
	// Subtracts the given number from this number, modulo the prime. Constant-time with respect to both values.
	public void subtract(FieldInt other) {
		int b = super.subtract(other, -1);  // Perform subtraction
		super.add(MODULUS, -b);  // Conditionally add modulus
	}
	
	
	// Doubles this number, modulo the prime. Constant-time with respect to this value.
	public void multiply2() {
		int c = super.shiftLeft1();
		super.subtract(MODULUS, -c | ~this.lessThan(MODULUS));  // Conditionally subtract modulus
	}
	
	
	// Triples this number, modulo the prime. Constant-time with respect to this value.
	public void multiply3() {
		FieldInt copy = new FieldInt(this);
		multiply2();
		add(copy);
	}
	
	
	// Squares this number, modulo the prime. Constant-time with respect to this value.
	public void square() {
		multiply(this);
	}
	
	
	// Multiplies the given number into this number, modulo the prime. Constant-time with respect to both values.
	public void multiply(FieldInt other) {
		// Compute raw product of this->value * other.value
		int[] product0 = new int[value.length * 2];
		{
			long carry = 0;
			int i = 0;
			for (; i < value.length; i++) {
				long sum = carry;
				int c = 0;
				for (int j = 0; j <= i; j++) {
					long prod = (value[j] & LONG_MASK) * (other.value[i - j] & LONG_MASK);
					sum += prod;
					c += lessThanAsBit(sum, prod);
				}
				product0[i] = (int)sum;
				carry = (long)c << 32 | sum >>> 32;
			}
			for (; i < product0.length - 1; i++) {
				long sum = carry;
				int c = 0;
				for (int j = value.length - 1; j >= 0 && i - j < value.length; j--) {
					long prod = (value[i - j] & LONG_MASK) * (other.value[j] & LONG_MASK);
					sum += prod;
					c += lessThanAsBit(sum, prod);
				}
				product0[i] = (int)sum;
				carry = (long)c << 32 | sum >>> 32;
			}
			product0[i] = (int)carry;
			assert((carry >>> 32) == 0);
		}
		
		// Barrett reduction algorithm begins here.
		// Multiply by floor(2^512 / MODULUS), which is 2^256 + 0x1000003d1
		int[] product1 = new int[value.length * 3];
		{
			int carry = 0;
			for (int i = 0; i < product1.length; i++) {
				long sum = carry;
				if (i < value.length * 2)
					sum += (product0[i] & LONG_MASK) * 0x3d1;
				if (i >= 1 && i < value.length * 2 + 1)
					sum += product0[i - 1] & LONG_MASK;
				if (i >= value.length)
					sum += product0[i - value.length] & LONG_MASK;
				product1[i] = (int)sum;
				carry = (int)(sum >>> 32);
			}
			assert(carry == 0);
		}
		
		// Virtually shift right by 512 bits, then multiply by MODULUS. Note that MODULUS = 2^256 - 0x1000003d1
		int p1Shift = value.length * 2;
		int[] product2 = new int[value.length * 2];
		{
			int borrow = 0;
			for (int i = 0; i < product2.length; i++) {
				long diff = -borrow;
				if (i < value.length)
					diff -= (product1[p1Shift + i] & LONG_MASK) * 0x3d1;
				if (i >= 1 && i < value.length + 1)
					diff -= product1[p1Shift + i - 1] & LONG_MASK;
				if (i >= value.length)
					diff += product1[p1Shift + i - value.length] & LONG_MASK;
				product2[i] = (int)diff;
				borrow = -(int)(diff >>> 32);
			}
			assert(borrow == 0);
		}
		
		// Compute product0 - product2
		int[] difference = new int[value.length + 1];
		{
			int borrow = 0;
			for (int i = 0; i < difference.length; i++) {
				long diff = (product0[i] & LONG_MASK) - (product2[i] & LONG_MASK) - borrow;
				difference[i] = (int)diff;
				borrow = -(int)(diff >>> 32);
			}
		}
		
		// Final conditional subtraction
		System.arraycopy(difference, 0, value, 0, value.length);
		int mask = (equalToAsBit(difference[value.length], 0) - 1) | ~this.lessThan(MODULUS);
		super.subtract(MODULUS, mask);
	}
	
	
	public void reciprocal(Uint256 other) {
		throw new UnsupportedOperationException();
	}
	
	
	public void reciprocal() {
		super.reciprocal(MODULUS, ZERO, ONE);
	}
	
	
	public void replace(FieldInt other, int mask) {
		super.replace(other, mask);
	}
	
	
	public int compareTo(FieldInt other) {
		return super.compareTo(other);
	}
	
	
	public int equalTo(FieldInt other) {
		return super.equalTo(other);
	}
	
	
	public int lessThan(FieldInt other) {
		return super.lessThan(other);
	}
	
	
	
	/* Static functions */
	
	// Returns 1 if x == y, otherwise 0.
	private static int equalToAsBit(int x, int y) {
		int z = x ^ y;
		return ~(z | -z) >>> 31;
	}
	
	
	// Returns 1 if x < y, otherwise 0.
	private static int lessThanAsBit(long x, long y) {
		return (int)(((~x & y) | ((~x ^ y) & (x - y))) >>> 63);
	}
	
	
	
	/* Constants */
	
	public static final Uint256 MODULUS = new Uint256 ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
	public static final FieldInt ZERO   = new FieldInt("0000000000000000000000000000000000000000000000000000000000000000");
	public static final FieldInt ONE    = new FieldInt("0000000000000000000000000000000000000000000000000000000000000001");
	
}
