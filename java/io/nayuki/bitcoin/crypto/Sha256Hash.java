/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package io.nayuki.bitcoin.crypto;

import java.util.Arrays;


/**
 * A 32-byte (256-bit) SHA-256 hash value. Immutable.
 * @see Sha256
 */
public final class Sha256Hash implements Comparable<Sha256Hash> {
	
	/* Constants */
	
	public static final int HASH_LENGTH = 32;
	
	
	
	/* Fields */
	
	private final byte[] hash;
	
	
	
	/* Constructors */
	
	// Length must equal 32
	public Sha256Hash(byte[] b) {
		if (b == null)
			throw new NullPointerException();
		if (b.length != HASH_LENGTH)
			throw new IllegalArgumentException();
		hash = b.clone();
	}
	
	
	// String is in byte-reversed order and has length 64
	public Sha256Hash(String s) {
		if (s == null)
			throw new NullPointerException();
		if (s.length() != HASH_LENGTH * 2 || !s.matches("[0-9a-fA-F]*"))
			throw new IllegalArgumentException("Invalid hash string");
		hash = new byte[HASH_LENGTH];
		for (int i = 0; i < hash.length; i++)
			hash[hash.length - 1 - i] = (byte)Integer.parseInt(s.substring(i * 2, (i + 1) * 2), 16);
	}
	
	
	
	/* Methods */
	
	public byte[] toBytes() {
		return hash.clone();
	}
	
	
	// Not constant-time
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		else if (!(obj instanceof Sha256Hash))
			return false;
		else
			return Arrays.equals(hash, ((Sha256Hash)obj).hash);
	}
	
	
	public int hashCode() {
		return (hash[0] & 0xFF) | (hash[1] & 0xFF) << 8 | (hash[2] & 0xFF) << 16 | hash[3] << 24;
	}
	
	
	// Not constant-time
	public int compareTo(Sha256Hash other) {
		for (int i = 0; i < hash.length; i++) {
			int temp = (hash[i] & 0xFF) - (other.hash[i] & 0xFF);
			if (temp != 0)
				return temp;
		}
		return 0;
	}
	
	
	// String is in byte-reversed order, in lowercase, having length 64
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (int i = hash.length - 1; i >= 0; i--)
			sb.append(String.format("%02x", hash[i]));
		return sb.toString();
	}
	
}
