/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */


/*
 * A point on the secp256k1 elliptic curve for Bitcoin use, in projective coordinates.
 * Contains methods for computing point addition, doubling, and multiplication, and testing equality.
 * The ordinary affine coordinates of a point is (x/z, y/z). Instances of this class are mutable.
 * 
 * Points MUST be normalized before comparing for equality. Example of correct usage:
 *   CurvePoint a(...);
 *   CurvePoint b(...);
 *   CurvePoint c(...);
 *   
 *   a.add(b);
 *   a.multiply(50);
 *   
 *   a.normalize();
 *   c.normalize();
 *   if (a == c) { ... }
 */
public final class CurvePoint {
	
	/* Fields */
	
	public final FieldInt x;
	public final FieldInt y;
	public final FieldInt z;  // The point is normalized iff (z = 1 OR (x,y,z)=(0,1,0))
	
	
	
	/* Constructors */
	
	// Constructs a normalized point (z=1) from the given coordinates. Constant-time with respect to the values.
	public CurvePoint(FieldInt x, FieldInt y) {
		this.x = new FieldInt(x);
		this.y = new FieldInt(y);
		this.z = new FieldInt(FieldInt.ONE);
	}
	
	
	public CurvePoint(CurvePoint other) {
		x = new FieldInt(other.x);
		y = new FieldInt(other.y);
		z = new FieldInt(other.z);
	}
	
	
	// Constructs a normalized point (z=1) from the given string coordinates. Not constant-time.
	public CurvePoint(String xStr, String yStr) {
		x = new FieldInt(xStr);
		y = new FieldInt(yStr);
		z = new FieldInt(FieldInt.ONE);
	}
	
	
	// Constructs the special "point at infinity" (normalized), which is used by ZERO and in multiply().
	private CurvePoint() {
		x = new FieldInt(FieldInt.ZERO);
		y = new FieldInt(FieldInt.ONE);
		z = new FieldInt(FieldInt.ZERO);
	}
	
	
	
	/* Arithmetic methods */
	
	// Adds the given curve point to this point. The resulting state is
	// usually not normalized. Constant-time with respect to both values.
	public void add(CurvePoint other) {
		/* 
		 * (Derived from http://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates)
		 * if (this == ZERO)
		 *   this = other
		 * else if (other == ZERO)
		 *   this = this
		 * else {
		 *   u0 = x0 * z1
		 *   u1 = x1 * z0
		 *   v0 = y0 * z1
		 *   v1 = y1 * z0
		 *   if (v0 == v1)  // Same y coordinates
		 *     this = (u0 != u1) ? ZERO : twice()
		 *   else {
		 *     u = u0 - u1
		 *     v = v0 - v1
		 *     w = z0 * z1
		 *     t = w * v^2 - (u0 + u1) * u^2
		 *     x' = u * t
		 *     y' = v * (u0 * u^2 - t) - v0 * u^3
		 *     z' = u^3 * w
		 *   }
		 * }
		 */
		int thisZero  = this .isZero();
		int otherZero = other.isZero();
		replace(other, thisZero);
		
		FieldInt u0 = new FieldInt(x);
		FieldInt u1 = new FieldInt(other.x);
		FieldInt v0 = new FieldInt(y);
		FieldInt v1 = new FieldInt(other.y);
		u0.multiply(other.z);
		u1.multiply(z);
		v0.multiply(other.z);
		v1.multiply(z);
		
		int sameX = u0.equalTo(u1);
		int sameY = v0.equalTo(v1);
		CurvePoint twiced = new CurvePoint(this);
		twiced.twice();
		
		FieldInt u = new FieldInt(u0);
		u.subtract(u1);
		FieldInt v = new FieldInt(v0);
		v.subtract(v1);
		FieldInt w = new FieldInt(z);
		w.multiply(other.z);
		
		FieldInt u2 = new FieldInt(u);
		u2.square();
		FieldInt u3 = new FieldInt(u2);
		u3.multiply(u);
		
		u1.add(u0);
		u1.multiply(u2);
		FieldInt t = new FieldInt(v);
		t.square();
		t.multiply(w);
		t.subtract(u1);
		
		int assign = -((1 - thisZero) & (1 - otherZero) & (1 - sameY));
		u.multiply(t);
		x.replace(u, assign);
		w.multiply(u3);
		z.replace(w, assign);
		u0.multiply(u2);
		u0.subtract(t);
		u0.multiply(v);
		v0.multiply(u3);
		u0.subtract(v0);
		y.replace(u0, assign);
		
		int cond = (1 - thisZero) & (1 - otherZero) & sameY;
		replace(ZERO  , cond & (1 - sameX));
		replace(twiced, cond & sameX);
	}
	
	
	// Doubles this curve point. The resulting state is usually
	// not normalized. Constant-time with respect to this value.
	public void twice() {
		/* 
		 * (Derived from http://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates)
		 * if (this == ZERO || y == 0)
		 *   this = ZERO
		 * else {
		 *   a = 0 (curve parameter)
		 *   s = 2 * y * z
		 *   t = 2 * x * y * s
		 *   u = 3 * x^2 + a * z^2
		 *   v = u^2 - 2 * t
		 *   x' = s * v
		 *   y' = u * (t - v) - 2 * (y * s)^2
		 *   z' = s^3
		 * }
		 */
		int zeroResult = isZero() | y.equalTo(FieldInt.ZERO);
		
		FieldInt s = new FieldInt(z);
		s.multiply(y);
		s.multiply2();
		
		FieldInt t = new FieldInt(s);
		t.multiply(y);
		t.multiply(x);
		t.multiply2();
		
		FieldInt t2 = new FieldInt(t);
		t2.multiply2();
		
		FieldInt u = new FieldInt(x);
		u.square();
		u.multiply3();
		
		FieldInt v = new FieldInt(u);
		v.square();
		v.subtract(t2);
		
		x.replace(v, -1);
		x.multiply(s);
		
		FieldInt s2 = new FieldInt(s);
		s2.square();
		
		z.replace(s2, -1);
		z.multiply(s);
		
		y.square();
		s2.multiply(y);
		s2.multiply2();
		t.subtract(v);
		u.multiply(t);
		u.subtract(s2);
		y.replace(u, -1);
		
		replace(ZERO, zeroResult);
	}
	
	
	// Multiplies this point by the given unsigned integer. The resulting state
	// is usually not normalized. Constant-time with respect to both values.
	public void multiply(Uint256 n) {
		// Precompute [this*0, this*1, ..., this*15]
		CurvePoint[] table = new CurvePoint[16];
		table[0] = new CurvePoint();
		table[1] = new CurvePoint(this);
		table[2] = new CurvePoint(this);
		table[2].twice();
		for (int i = 3; i < table.length; i++) {
			table[i] = new CurvePoint(table[i - 1]);
			table[i].add(this);
		}
		
		// Process 4 bits per iteration (windowed method)
		this.replace(ZERO, 1);
		for (int i = 256 - 4; i >= 0; i -= 4) {
			if (i != 256 - 4) {
				for (int j = 0; j < 4; j++)
					this.twice();
			}
			int inc = (n.value[i >>> 5] >>> (i & 31)) & 15;
			CurvePoint q = new CurvePoint();
			for (int j = 0; j < table.length; j++)
				q.replace(table[j], equalToAsBit(j, inc));
			this.add(q);
		}
	}
	
	
	// Normalizes the coordinates of this point. If z != 0, then (x', y', z') = (x/z, y/z, 1);
	// otherwise special logic occurs. Constant-time with respect to this value.
	public void normalize() {
		int nonzero = z.equalTo(FieldInt.ZERO) + 1;
		CurvePoint norm = new CurvePoint(this);
		norm.z.reciprocal();
		norm.x.multiply(norm.z);
		norm.y.multiply(norm.z);
		norm.z.replace(FieldInt.ONE, -1);
		x.replace(FieldInt.ONE, ~x.equalTo(FieldInt.ZERO));
		y.replace(FieldInt.ONE, ~y.equalTo(FieldInt.ZERO));
		replace(norm, nonzero);
	}
	
	
	// Conditionally replaces this point's coordinates with the given point. Constant-time with respect to both values.
	public void replace(CurvePoint other, int enable) {
		assert (enable >>> 1) == 0;
		int mask = -enable;
		x.replace(other.x, mask);
		y.replace(other.y, mask);
		z.replace(other.z, mask);
	}
	
	
	// Tests whether this point is on the elliptic curve. This point needs to be normalized before the method is called.
	// Zero is considered to be off the curve. Constant-time with respect to this value.
	public int isOnCurve() {
		FieldInt left = new FieldInt(y);
		left.square();
		FieldInt right = new FieldInt(x);
		right.square();
		right.add(A);
		right.multiply(x);
		right.add(B);
		return left.equalTo(right) & isZero();
	}
	
	
	// Tests whether this point is equal to the special zero point. This point need not be normalized. Constant-time with respect to this value.
	// This method is equivalent to, but more convenient than: { CurvePoint temp(*this); temp.normalize(); return temp == ZERO; }
	public int isZero() {
		return -(x.equalTo(FieldInt.ZERO) & ~y.equalTo(FieldInt.ZERO) & z.equalTo(FieldInt.ZERO));
	}
	
	
	public int hashCode() {
		return x.hashCode() + y.hashCode() + z.hashCode();
	}
	
	
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		else if (!(obj instanceof CurvePoint))
			return false;
		else {
			CurvePoint other = (CurvePoint)obj;
			return x.equals(other.x) && y.equals(other.y) && z.equals(other.z);
		}
	}
	
	
	public String toString() {
		return String.format("(%s, %s, %s)", x, y, z);
	}
	
	
	// Tests whether this point equals the given point in all 3 coordinates. This comparison is
	// meaningful only if both points are normalized. Constant-time with respect to both values.
	public int equalTo(CurvePoint other) {
		return x.equalTo(other.x) & y.equalTo(other.y) & z.equalTo(other.z);
	}
	
	
	// Serializes this point in compressed format. Constant-time with respect to this value.
	public byte[] toCompressedPoint() {
		byte[] result = new byte[33];
		result[0] = (byte)((y.value[0] & 1) + 0x02);
		System.arraycopy(x.toBigEndianBytes(), 0, result, 1, 32);
		return result;
	}
	
	
	// Returns 1 if x == y, otherwise 0.
	private static int equalToAsBit(int x, int y) {
		int z = x ^ y;
		return ~(z | -z) >>> 31;
	}
	
	
	/* Class constants */
	
	public static final FieldInt A    = new FieldInt("0000000000000000000000000000000000000000000000000000000000000000");  // Curve equation parameter
	public static final FieldInt B    = new FieldInt("0000000000000000000000000000000000000000000000000000000000000007");  // Curve equation parameter
	public static final Uint256 ORDER = new Uint256 ("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");  // Order of base point
	public static final CurvePoint G = new CurvePoint(
		new FieldInt("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
		new FieldInt("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));  // Base point (normalized)
	public static final CurvePoint ZERO = new CurvePoint();  // Dummy point at infinity (normalized)
	
}
