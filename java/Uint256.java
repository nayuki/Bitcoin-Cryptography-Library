/* 
 * A plain unsigned 256-bit integer.
 */
public final class Uint256 extends AbstractInt256 implements Comparable<Uint256> {
	
	/* Constructors */
	
	public Uint256(Uint256 other) {
		super(other);
	}
	
	
	public Uint256(String s) {
		super(s);
	}
	
	
	public Uint256(byte[] b, int off) {
		super(b, off);
	}
	
	
	
	/* Arithmetic methods */
	
	// Adds the given number into this number, modulo 2^256. Constant-time with respect to both values.
	public void add(Uint256 other) {
		super.add(other, -1);
	}
	
	
	// Subtracts the given number from this number, modulo 2^256. Constant-time with respect to both values.
	public void subtract(Uint256 other) {
		super.subtract(other, -1);
	}
	
	
	// Computes the multiplicative inverse of this number with respect to the given modulus.
	// If this number is zero, the reciprocal is zero. Constant-time with respect to this value.
	// The modulus must be odd and coprime to this number. This number must be less than the modulus.
	public void reciprocal(Uint256 modulus) {
		super.reciprocal(modulus, ZERO, ONE);
	}
	
	
	/* Miscellaneous methods */
	
	public void replace(Uint256 other, int mask) {
		super.replace(other, mask);
	}
	
	
	public int compareTo(Uint256 other) {
		return super.compareTo(other);
	}
	
	
	
	/* Constants */
	
	public static final Uint256 ZERO = new Uint256("0000000000000000000000000000000000000000000000000000000000000000");
	public static final Uint256 ONE  = new Uint256("0000000000000000000000000000000000000000000000000000000000000001");
	
}
