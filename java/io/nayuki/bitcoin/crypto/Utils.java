/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package io.nayuki.bitcoin.crypto;


final class Utils {
	
	public static byte[] hexToBytes(String s) {
		if (s.length() % 2 != 0)
			throw new IllegalArgumentException();
		
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < s.length(); i += 2) {
			if (s.charAt(i) == '+' || s.charAt(i) == '-')
				throw new IllegalArgumentException();
			b[i / 2] = (byte)Integer.parseInt(s.substring(i, i + 2), 16);
		}
		return b;
	}
	
	
	
	private Utils() {}  // Not instantiable
	
}
