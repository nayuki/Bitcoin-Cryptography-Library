import static org.junit.Assert.assertEquals;
import java.math.BigInteger;
import java.util.Random;
import org.junit.Test;


public final class Int256MathTest {
	
	@Test public void testComparison() {
		String[][] cases = {
			{"0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"},
			{"0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000001"},
			{"0000000000000000000000000000000000000000000000000000000000000080", "0000000000000000000000000000000000000000000000000000000000000000"},
			{"ff00000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"},
			{"f000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"},
			{"0123400000000000000000000000000000000000000000000000000000000000", "0123400000000000000000000000000000000000000000000000000000000000"},
			{"0000000000000000000000000000000000000000000000000000000000000000", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"},
			{"00000000000000000000000000000000000000000000000000000000000000ff", "ff00000000000000000000000000000000000000000000000000000000000000"},
		};
		for (int i = 0; i < 30000; i++) {
			String s = i < cases.length ? cases[i][0] : randomInt256Str();
			String t = i < cases.length ? cases[i][1] : randomInt256Str();
			TestInt x = new TestInt(s);
			TestInt y = new TestInt(t);
			BigInteger a = toBigInt(s);
			BigInteger b = toBigInt(t);
			int cmp = a.compareTo(b);
			assertEquals(cmp == 0 ? 1 : 0, Int256Math.equalTo (x.val, x.off, y.val, y.off));
			assertEquals(cmp <  0 ? 1 : 0, Int256Math.lessThan(x.val, x.off, y.val, y.off));
			assertEquals(cmp >  0 ? 1 : 0, Int256Math.lessThan(y.val, y.off, x.val, x.off));
		}
	}
	
	
	@Test public void testUintAdd() {
		String[][] cases = {
			{"0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"},
			{"0000000000000000000000000000000000000000000000000000000080000000", "0000000000000000000000000000000000000000000000000000000080000000"},
			{"000000000000000000000000000000000000000000000fffffffffffffffffff", "0000000000000000000000000000000000000000000000000000000000000001"},
			{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", "0000000000000000000000000000000000000000000000000000000000000001"},
			{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0000000000000000000000000000000000000000000000000000000000000001"},
			{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
			{"ff00000000000000000000000000000000000000000000000000000000000000", "ff00000000000000000000000000000000000000000000000000000000000000"},
		};
		for (int i = 0; i < 30000; i++) {
			String s = i < cases.length ? cases[i][0] : randomInt256Str();
			String t = i < cases.length ? cases[i][1] : randomInt256Str();
			TestInt x = new TestInt(s);
			TestInt y = new TestInt(t);
			BigInteger a = toBigInt(s);
			BigInteger b = toBigInt(t);
			BigInteger c = a.add(b);
			assertEquals(0, Int256Math.uintAdd(x.val, x.off, y.val, y.off, 0));
			assertEqualsBigInt256(a, x.val, x.off);
			assertEquals(c.shiftRight(256).intValue(), Int256Math.uintAdd(x.val, x.off, y.val, y.off, 1));
			assertEqualsBigInt256(c, x.val, x.off);
		}
	}
	
	
	@Test public void testUintSubtract() {
		String[][] cases = {
			{"0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"},
			{"0000000000000000000000000000000000000000000000000000000000000003", "0000000000000000000000000000000000000000000000000000000000000002"},
			{"0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000001"},
			{"0000000000000000000000000000000000000000000000000000000000000000", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		};
		for (int i = 0; i < 30000; i++) {
			String s = i < cases.length ? cases[i][0] : randomInt256Str();
			String t = i < cases.length ? cases[i][1] : randomInt256Str();
			TestInt x = new TestInt(s);
			TestInt y = new TestInt(t);
			BigInteger a = toBigInt(s);
			BigInteger b = toBigInt(t);
			BigInteger c = a.subtract(b);
			assertEquals(0, Int256Math.uintSubtract(x.val, x.off, y.val, y.off, 0));
			assertEqualsBigInt256(a, x.val, x.off);
			assertEquals(-c.shiftRight(256).intValue(), Int256Math.uintSubtract(x.val, x.off, y.val, y.off, 1));
			assertEqualsBigInt256(c, x.val, x.off);
		}
	}
	
	
	@Test public void testUintShiftLeft1() {
		String[] cases = {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000001",
			"0000000000000000000000000000000000000000000000000000000080000000",
			"00000000000000000000000000000000000000000000000000000000ffffffff",
			"000abcdef0000000000000000000000000000000000000000000000000000000",
			"8000000000000000000000000000000000000000000000000000000000000000",
			"ffff000000000000000000000000000000000000000000000000000000000000",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		};
		for (int i = 0; i < 100000; i++) {
			String s = i < cases.length ? cases[i] : randomInt256Str();
			TestInt x = new TestInt(s);
			BigInteger a = toBigInt(s);
			BigInteger b = a.shiftLeft(1);
			assertEquals(a.testBit(255) ? 1 : 0, Int256Math.uintShiftLeft1(x.val, x.off));
			assertEqualsBigInt256(b, x.val, x.off);
		}
	}
	
	
	@Test public void testUintShiftRight1() {
		String[] cases = {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000001",
			"0000000000000000000000000000000000000000000000000000000080000000",
			"00000000000000000000000000000000000000000000000000000000ffffffff",
			"000abcdef0000000000000000000000000000000000000000000000000000000",
			"8000000000000000000000000000000000000000000000000000000000000000",
			"ffff000000000000000000000000000000000000000000000000000000000000",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		};
		for (int i = 0; i < 100000; i++) {
			String s = i < cases.length ? cases[i] : randomInt256Str();
			TestInt x = new TestInt(s);
			BigInteger a = toBigInt(s);
			BigInteger b = a.shiftRight(1);
			Int256Math.uintShiftRight1(x.val, x.off, 0);
			assertEqualsBigInt256(a, x.val, x.off);
			Int256Math.uintShiftRight1(x.val, x.off, 1);
			assertEqualsBigInt256(b, x.val, x.off);
		}
	}
	
	
	@Test public void testReciprocalRandomly() {
		for (int i = 0; i < 300; i++) {
			BigInteger mod;  // Choose an odd number at least 128 bits long
			do mod = new BigInteger(192 + rand.nextInt(65), rand);
			while (!mod.testBit(0) || mod.bitLength() < 128);
			
			for (int j = 0; j < 30; j++) {
				BigInteger a;  // Choose 'a' in [0, mod) that is coprime to mod
				do a = new BigInteger(mod.bitLength(), rand);
				while (!a.gcd(mod).equals(BigInteger.ONE));
				a = a.mod(mod);
				
				TestInt x = new TestInt(String.format("%064x", a));
				TestInt y = new TestInt(String.format("%064x", mod));
				Int256Math.reciprocal(x.val, x.off, y.val, y.off, new int[40], 0);
				BigInteger b = a.modInverse(mod);
				assertEqualsBigInt256(b, x.val, x.off);
			}
		}
	}
	
	
	/*---- Helper definitions ----*/
	
	private static String randomInt256Str() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 8; i++) {
			int word;
			double type = rand.nextDouble();
			if (type < 0.2)
				word = rand.nextInt();
			else {
				word = rand.nextInt(10);
				if (type < 0.4)
					word = ~word;
			}
			sb.append(String.format("%08x", word));
		}
		return sb.toString();
	}
	
	
	private static void assertEqualsBigInt256(BigInteger num, int[] val, int off) {
		for (int i = 0; i < 8; i++)
			assertEquals(num.shiftRight(i * 32).intValue(), val[off + i]);
	}
	
	
	private static BigInteger toBigInt(String s) {
		return new BigInteger(s, 16);
	}
	
	
	private static Random rand = new Random();
	
	
	
	private static class TestInt {
		
		public int[] val;
		public int off;
		
		
		// Constructs an int256 array from the given hexadecimal string,
		// using a random offset that is a multiple of 8.
		// The offset ensures that methods under test don't assume
		// an offset of 0 or mix up offsets of different arguments.
		public TestInt(String s) {
			off = rand.nextInt(4) * 8;
			val = new int[off + 8];
			for (int i = 0; i < 8; i++)
				val[off + i] = (int)Long.parseLong(s.substring((7 - i) * 8, (8 - i) * 8), 16);
		}
		
	}
	
}
