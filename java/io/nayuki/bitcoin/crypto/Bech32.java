/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package io.nayuki.bitcoin.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;


/**
 * Converts data to and from Bech32 strings. Not instantiable.
 */
public final class Bech32 {
	
	/*---- Static functions for segregated witness addresses ----*/
	
	/**
	 * Encodes the specified segregated witness output into a Bech32 address string.
	 * @param humanPart the prefix given to the resulting string, which should be a mnemonic for
	 * the cryptocurrency name; must be not {@code null}, must have length in the range [1, 83],
	 * must have all characters in the ASCII range [33, 126] but excluding uppercase characters
	 * @param witVer the witness version number; must be in the range [0, 16]
	 * @param witProg the raw witness program, without the length byte;
	 * must be not {@code null}, must have length in the range [2, 40]
	 * @return the Bech32 address of the specified segregated witness output;
	 * the result is entirely ASCII, lacks uppercase, and at most 90 characters long
	 * @throws NullPointerException if humanPart or witProg is {@code null}
	 * @throws IllegalArgumentException if any argument violates the stated preconditions,
	 * or the combination of humanPart and witProg would make the result exceed 90 characters
	 */
	public static String segwitToBech32(String humanPart, int witVer, byte[] witProg) {
		// Check arguments
		Objects.requireNonNull(humanPart);
		Objects.requireNonNull(witProg);
		if (witVer < 0 || witVer > 16)
			throw new IllegalArgumentException("Invalid witness version");
		if (witProg.length < 2 || witProg.length > 40)
			throw new IllegalArgumentException("Invalid witness program length");
		
		// Create buffer of 5-bit groups
		ByteArrayOutputStream data = new ByteArrayOutputStream();  // Every element is uint5
		assert (witVer >>> 5) == 0;
		data.write(witVer);  // uint5
		
		// Variables/constants for bit processing
		final int IN_BITS = 8;
		final int OUT_BITS = 5;
		int inputIndex = 0;
		int bitBuffer = 0;  // Topmost bitBufferLen bits are valid; remaining lower bits are zero
		int bitBufferLen = 0;  // Always in the range [0, 12]
		
		// Repack all 8-bit bytes into 5-bit groups, adding padding
		while (inputIndex < witProg.length || bitBufferLen > 0) {
			assert 0 <= bitBufferLen && bitBufferLen <= IN_BITS + OUT_BITS - 1;
			assert (bitBuffer << bitBufferLen) == 0;
			
			if (bitBufferLen < OUT_BITS) {
				if (inputIndex < witProg.length) {  // Read a byte
					bitBuffer |= (witProg[inputIndex] & 0xFF) << (32 - IN_BITS - bitBufferLen);
					inputIndex++;
					bitBufferLen += IN_BITS;
				} else  // Create final padding
					bitBufferLen = OUT_BITS;
			}
			assert bitBufferLen >= 5;
			
			// Write a 5-bit group
			data.write(bitBuffer >>> (32 - OUT_BITS));  // uint5
			bitBuffer <<= OUT_BITS;
			bitBufferLen -= OUT_BITS;
		}
		return bitGroupsToBech32(humanPart, data.toByteArray());
	}
	
	
	/**
	 * Decodes the specified Bech32 address string into a segregated witness output.
	 * The result is a triple (human-readable part, witness version, witness program).
	 * @param s the Bech32 string to decode, which must be either
	 * all-lowercase or all-uppercase, and at most 90 characters long
	 * @return a triple where index 0 is a {@code String} representing the human-readable part
	 * (which obeys all the rules as stated in the encoder), index 1 is an {@code Integer}
	 * representing the witness version (in the range [0, 16]), and index 2 is a new
	 * {@code byte[]} containing the witness program (whose length is in the range [2, 40];
	 * the array contains 8-bit data)
	 * @throws NullPointerException if the string is {@code null}
	 * @throws IllegalArgumentException if the string is too long, has mixed case,
	 * lacks a separator, has an invalid human-readable part, has non-base-32
	 * characters in the data, lacks a full checksum, has an incorrect checksum,
	 * has an invalid witness version, or has an invalid length of witness program
	 */
	public static Object[] bech32ToSegwit(String s) {
		Object[] decoded = bech32ToBitGroups(s);
		byte[] data = (byte[])decoded[1];
		
		// Extract leading value representing version
		if (data.length < 1)
			throw new IllegalArgumentException("Missing witness version");
		int witVer = data[0];
		if (witVer < 0 || witVer > 16)
			throw new IllegalArgumentException("Invalid witness version");
		
		// Initialize output array
		byte[] witProg = new byte[(data.length - 1) * 5 / 8];  // Discard version prefix and padding suffix
		if (witProg.length < 2 || witProg.length > 40)
			throw new IllegalArgumentException("Invalid witness program length");
		
		// Variables/constants for bit processing
		final int IN_BITS = 5;
		final int OUT_BITS = 8;
		int outputIndex = 0;
		int bitBuffer = 0;  // Topmost bitBufferLen bits are valid; remaining lower bits are zero
		int bitBufferLen = 0;  // Always in the range [0, 10]
		
		// Repack all 5-bit groups into 8-bit bytes, discarding padding
		for (int i = 1; i < data.length; i++) {
			int b = data[i];
			assert 0 <= bitBufferLen && bitBufferLen <= IN_BITS * 2;
			assert (bitBuffer << bitBufferLen) == 0;
			
			bitBuffer |= b << (32 - IN_BITS - bitBufferLen);
			bitBufferLen += IN_BITS;
			
			if (bitBufferLen >= OUT_BITS) {
				witProg[outputIndex] = (byte)(bitBuffer >>> (32 - OUT_BITS));
				outputIndex++;
				bitBuffer <<= OUT_BITS;
				bitBufferLen -= OUT_BITS;
			}
		}
		
		// Final checks and return
		assert outputIndex == witProg.length;
		if (bitBuffer != 0)
			throw new IllegalArgumentException("Non-zero padding");
		return new Object[]{decoded[0], witVer, witProg};
	}
	
	
	
	/*---- Static functions for bit groups ----*/
	
	/**
	 * Encodes the specified human-readable part prefix plus
	 * the specified array of 5-bit data into a Bech32 string.
	 * @param humanPart the prefix given to the resulting string, which should be a mnemonic for
	 * the cryptocurrency name; must be not {@code null}, must have length in the range [1, 83],
	 * must have all characters in the ASCII range [33, 126] but excluding uppercase characters
	 * @param data a non-{@code null} sequence of zero or more values, where each value is a uint5
	 * @return the Bech32 string representing the specified two pieces of data;
	 * the result is entirely ASCII, lacks uppercase, and at most 90 characters long
	 * @throws NullPointerException if the string or data is {@code null}
	 * @throws IllegalArgumentException if any argument violates the stated
	 * preconditions, or {@code humanPart.length() + data.length > 83}
	 */
	public static String bitGroupsToBech32(String humanPart, byte[] data) {
		// Check arguments
		Objects.requireNonNull(humanPart);
		Objects.requireNonNull(data);
		char[] human = humanPart.toCharArray();
		checkHumanReadablePart(human);
		for (byte b : data) {
			if ((b >>> 5) != 0)
				throw new IllegalArgumentException("Expected 5-bit groups");
		}
		if (human.length + 1 + data.length + 6 > 90)
			throw new IllegalArgumentException("Output too long");
		
		// Compute checksum
		int checksum;
		try {
			ByteArrayOutputStream temp = expandHumanReadablePart(human);  // Every element is uint5
			temp.write(data);
			temp.write(new byte[CHECKSUM_LEN]);
			checksum = polymod(temp.toByteArray()) ^ 1;
		} catch (IOException e) {
			throw new AssertionError(e);  // Impossible
		}
		
		// Encode to base-32
		StringBuilder sb = new StringBuilder(humanPart).append('1');
		for (byte b : data)
			sb.append(ALPHABET.charAt(b));
		for (int i = 0; i < CHECKSUM_LEN; i++) {
			int b = (checksum >>> ((CHECKSUM_LEN - 1 - i) * 5)) & 0x1F;  // uint5
			sb.append(ALPHABET.charAt(b));
		}
		return sb.toString();
	}
	
	
	/**
	 * Decodes the specified Bech32 string into a human-readable part and an array of 5-bit data.
	 * @param s the Bech32 string to decode, which must be either
	 * all-lowercase or all-uppercase, and at most 90 characters long
	 * @return a pair where index 0 is a {@code String} representing the human-readable part
	 * (which obeys all the rules as stated in the encoder), and index 1 is a new
	 * {@code byte[]} containing the 5-bit data (whose length is in the range [0, 82])
	 * @throws NullPointerException if the string is {@code null}
	 * @throws IllegalArgumentException if the string is too long, has mixed case,
	 * lacks a separator, has an invalid human-readable part, has non-base-32
	 * characters in the data, lacks a full checksum, or has an incorrect checksum
	 */
	public static Object[] bech32ToBitGroups(String s) {
		// Basic checks
		Objects.requireNonNull(s);
		if (s.length() > 90)
			throw new IllegalArgumentException("Input too long");
		
		{  // Normalize to lowercase, rejecting mixed case
			boolean hasLower = false;
			char[] temp = s.toCharArray();
			for (int i = 0; i < temp.length; i++) {
				char c = temp[i];
				hasLower |= 'a' <= c && c <= 'z';
				if ('A' <= c && c <= 'Z') {
					if (hasLower)
						throw new IllegalArgumentException("String has mixed case");
					temp[i] += 'a' - 'A';
				}
			}
			s = new String(temp);
		}
		
		// Split human-readable part and data
		String humanPart;
		{
			int i = s.lastIndexOf('1');
			if (i == -1)
				throw new IllegalArgumentException("No separator found");
			humanPart = s.substring(0, i);
			s = s.substring(i + 1);
		}
		char[] human = humanPart.toCharArray();
		checkHumanReadablePart(human);
		
		// Decode from base-32
		if (s.length() < CHECKSUM_LEN)
			throw new IllegalArgumentException("Data too short");
		byte[] dataAndCheck = new byte[s.length()];  // Every element is uint5
		for (int i = 0; i < s.length(); i++) {
			int index = ALPHABET.indexOf(s.charAt(i));
			if (index == -1)
				throw new IllegalArgumentException("Invalid data character");
			dataAndCheck[i] = (byte)index;
		}
		
		try {  // Verify checksum
			ByteArrayOutputStream temp = expandHumanReadablePart(human);
			temp.write(dataAndCheck);
			if (polymod(temp.toByteArray()) != 1)
				throw new IllegalArgumentException("Checksum mismatch");
		} catch (IOException e) {
			throw new AssertionError(e);  // Impossible
		}
		
		// Remove checksum, return pair
		byte[] data = Arrays.copyOf(dataAndCheck, dataAndCheck.length - CHECKSUM_LEN);
		return new Object[]{humanPart, data};
	}
	
	
	// Throws an exception if any of the following:
	// * Its length is outside the range [1, 83].
	// * It contains non-ASCII characters outside the range [33, 126].
	// * It contains uppercase characters.
	// Otherwise returns silently.
	static void checkHumanReadablePart(char[] s) {
		int n = s.length;
		if (n < 1 || n > 83)
			throw new IllegalArgumentException("Invalid length of human-readable part string");
		
		for (char c : s) {
			if (c < 33 || c > 126)
				throw new IllegalArgumentException("Invalid character in human-readable part string");
			if ('A' <= c && c <= 'Z')
				throw new IllegalArgumentException("Human-readable part string must be lowercase");
		}
	}
	
	
	// Returns a new byte buffer containing uint5 values, representing the given string
	// expanded into the prefix data for the purpose of computing/verifying a checksum.
	private static ByteArrayOutputStream expandHumanReadablePart(char[] s) {
		ByteArrayOutputStream result = new ByteArrayOutputStream();  // Every element is uint5
		for (char c : s)
			result.write(c >>> 5);  // uint3 from high bits
		result.write(0);
		for (char c : s)
			result.write(c & 0x1F);  // uint5 from low bits
		return result;
	}
	
	
	// Computes the polynomial remainder of the given sequence of 5-bit groups. The result is a uint30.
	private static int polymod(byte[] data) {
		int result = 1;
		for (byte b : data) {
			assert 0 <= b && b < 32;  // uint5
			int x = result >>> 25;
			result = ((result & ((1 << 25) - 1)) << 5) | b;
			for (int i = 0; i < GENERATOR.length; i++)
				result ^= ((x >>> i) & 1) * GENERATOR[i];
			assert (result >>> 30) == 0;  // uint30
		}
		return result;
	}
	
	
	
	/*---- Class constants ----*/
	
	// The base-32 alphabet. Designed so that visually similar characters having small bit differences.
	private static final String ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	
	// For computing/verifying checksums. Each element is a uint30.
	private static final int[] GENERATOR = {0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3};
	
	// Number of uint5 groups. Do not modify.
	private static final int CHECKSUM_LEN = 6;
	
	
	
	/*---- Miscellaneous ----*/
	
	private Bech32() {}  // Not instantiable
	
}
