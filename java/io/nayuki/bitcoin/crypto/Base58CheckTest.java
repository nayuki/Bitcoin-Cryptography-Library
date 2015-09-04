/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package io.nayuki.bitcoin.crypto;

import java.security.SecureRandom;
import java.util.Random;
import org.junit.Assert;
import org.junit.Test;


/**
 * Tests the Base58Check conversion.
 * @see Base58Check
 */
public final class Base58CheckTest {
	
	@Test public void testBasic() {
		test("", "3QJmnh");
		test("FF", "VrZDWwe");
		test("00", "1Wh4bh");
		test("0000", "112edB6q");
		test("00010966776006953D5567439E5E39F86A0D273BEE", "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");
	}
	
	
	@Test public void testRandom() {
		for (int i = 0; i < 10000; i++) {
			byte[] b = new byte[rand.nextInt(300) + 1];
			rand.nextBytes(b);
			String s = Base58Check.bytesToBase58(b);
			Assert.assertArrayEquals(b, Base58Check.base58ToBytes(s));
		}
	}
	
	
	@Test public void testRandomCorrupt() {
		for (int i = 0; i < 3000; i++) {
			byte[] b = new byte[rand.nextInt(300) + 1];
			rand.nextBytes(b);
			byte[] temp = Base58Check.addCheckHash(b);
			boolean changed = false;
			for (int j = 0; j < 4; j++) {
				if (rand.nextDouble() < 0.8) {
					temp[temp.length - 1 - j] += rand.nextInt(255) + 1;
					changed = true;
				}
			}
			if (changed) {
				try {
					String bad = Base58Check.rawBytesToBase58(temp);
					String good = Base58Check.bytesToBase58(b);
					Assert.assertFalse(bad.equals(good));
					Base58Check.base58ToBytes(bad);
					Assert.fail();
				} catch (IllegalArgumentException e) {}  // Pass
			}
		}
	}
	
	
	private static void test(String hexBytes, String expectBase58) {
		byte[] bytes = Utils.hexToBytes(hexBytes);
		Assert.assertEquals(expectBase58, Base58Check.bytesToBase58(bytes));
		Assert.assertArrayEquals(bytes, Base58Check.base58ToBytes(expectBase58));
	}
	
	
	private static Random rand = new SecureRandom();
	
}
