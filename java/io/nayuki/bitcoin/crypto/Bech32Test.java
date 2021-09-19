/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package io.nayuki.bitcoin.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Assert;
import org.junit.Test;


/**
 * Tests the functions of the Bech32 class.
 * @see Bech32
 */
public final class Bech32Test {
	
	@Test public void testSegwitToAndFromBech32() {
		String[][] cases = {
			{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc", "0", "751E76E8199196D454941C45D1B3A323F1433BD6"},
			{"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "tb", "0", "751E76E8199196D454941C45D1B3A323F1433BD6"},
			{"bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "bc", "0", "1863143C14C5166804BD19203356DA136C985678CD4D27A1B8C6329604903262"},
			{"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "tb", "0", "1863143C14C5166804BD19203356DA136C985678CD4D27A1B8C6329604903262"},
		};
		for (String[] cs : cases) {
			assertEquals(cs[0], Bech32.segwitToBech32(cs[1], Integer.parseInt(cs[2]), Utils.hexToBytes(cs[3])));
			Object[] temp = Bech32.bech32ToSegwit(cs[0]);
			assertEquals(cs[1], temp[0]);
			assertEquals(Integer.valueOf(cs[2]), temp[1]);
			assertArrayEquals((byte[])temp[2], Utils.hexToBytes(cs[3]));
		}
	}
	
	
	@Test public void testBitGroupsToAndFromBech32() {
		Object[][] cases = {
			{"a12uel5l", "a", new byte[0]},
			{"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs", "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", new byte[0]},
			{"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", "abcdef", new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31}},
			{"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j", "1", new byte[82]},
			{"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", "split", new byte[]{24,23,25,24,22,28,1,16,11,29,8,25,23,29,19,13,16,23,29,22,25,28,1,16,11,3,25,29,27,25,3,3,29,19,11,25,3,3,25,13,24,29,1,25,3,3,25,13}},
			{"?1ezyfcl", "?", new byte[0]},
		};
		for (Object[] cs : cases) {
			assertEquals(cs[0], Bech32.bitGroupsToBech32((String)cs[1], (byte[])cs[2]));
			Object[] temp = Bech32.bech32ToBitGroups((String)cs[0]);
			assertEquals(cs[1], temp[0]);
			assertArrayEquals((byte[])cs[2], (byte[])temp[1]);
		}
	}
	
	
	@Test public void testCheckHumanReadablePartValid() {
		String[] cases = {
			"a",
			"bc",
			"1",
			"111",
			"the-quick.brown*fox",
		};
		for (String cs : cases)
			Bech32.checkHumanReadablePart(cs.toCharArray());
	}
	
	
	@Test public void testCheckHumanReadablePartInvalid() {
		String[] cases = {
			"",
			"012345678901234567890123456789012345678901234567890123456789012345678901234567890123",
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
			"A",
			"xXx",
			"\u0020",
			"\u007F",
			"\u0080",
			"\u2000",
			"\uD852\uDF62",
		};
		for (String cs : cases) {
			try {
				Bech32.checkHumanReadablePart(cs.toCharArray());
				Assert.fail();
			} catch (IllegalArgumentException e) {}  // Pass
		}
	}
	
}
