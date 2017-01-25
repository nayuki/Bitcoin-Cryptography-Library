/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package io.nayuki.bitcoin.crypto;

import static java.lang.Long.rotateRight;
import java.util.Arrays;
import java.util.Objects;


/**
 * Computes the SHA-512 hash or HMAC of an array of bytes. Not instantiable.
 */
public final class Sha512 {
	
	private static final int BLOCK_LEN = 128;  // In bytes
	
	
	
	/*---- Static functions ----*/
	
	/**
	 * Computes and returns a 64-byte (512-bit) hash of the specified binary message.
	 * Each call will return a new byte array object instance.
	 * @param msg the message to compute the hash of
	 * @return a 64-byte array representing the message's SHA-512 hash
	 * @throws NullPointerException if the message is {@code null}
	 */
	public static byte[] getHash(byte[] msg) {
		// Compress whole message blocks
		Objects.requireNonNull(msg);
		long[] state = {
			0x6A09E667F3BCC908L, 0xBB67AE8584CAA73BL, 0x3C6EF372FE94F82BL, 0xA54FF53A5F1D36F1L,
			0x510E527FADE682D1L, 0x9B05688C2B3E6C1FL, 0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L};
		int off = msg.length / BLOCK_LEN * BLOCK_LEN;
		compress(state, msg, off);
		
		// Final blocks, padding, and length
		byte[] block = new byte[BLOCK_LEN];
		System.arraycopy(msg, off, block, 0, msg.length - off);
		off = msg.length % block.length;
		block[off] = (byte)0x80;
		off++;
		if (off + 16 > block.length) {
			compress(state, block, block.length);
			Arrays.fill(block, (byte)0);
		}
		long len = (long)msg.length << 3;
		for (int i = 0; i < 8; i++)
			block[block.length - 1 - i] = (byte)(len >>> (i * 8));
		compress(state, block, block.length);
		
		// Int64 array to bytes in big endian
		byte[] result = new byte[state.length * 8];
		for (int i = 0; i < result.length; i++)
			result[i] = (byte)(state[i / 8] >>> ((7 - i % 8) * 8));
		return result;
	}
	
	
	/**
	 * Computes and returns a 64-byte (512-bit) message authentication code of the
	 * specified message with the specified key, using the HMAC-SHA-512 algorithm.
	 * Each call will return a new byte array object instance.
	 * @param key the secret key
	 * @param msg the message
	 * @throws NullPointerException if the key or message is {@code null}
	 * @return a 64-byte array representing the HMAC value
	 */
	public static byte[] getHmac(byte[] key, byte[] msg) {
		Objects.requireNonNull(key);
		Objects.requireNonNull(msg);
		if (key.length > BLOCK_LEN)
			key = getHash(key);
		if (key.length < BLOCK_LEN)  // Note: Do not change to else-if
			key = Arrays.copyOf(key, BLOCK_LEN);
		if (key.length != BLOCK_LEN)
			throw new AssertionError();
		
		byte[] innerMsg = new byte[BLOCK_LEN + msg.length];
		for (int i = 0; i < key.length; i++)
			innerMsg[i] = (byte)(key[i] ^ 0x36);
		System.arraycopy(msg, 0, innerMsg, BLOCK_LEN, msg.length);
		byte[] innerHash = getHash(innerMsg);
		
		byte[] outerMsg = new byte[BLOCK_LEN + innerHash.length];
		for (int i = 0; i < key.length; i++)
			outerMsg[i] = (byte)(key[i] ^ 0x5C);
		System.arraycopy(innerHash, 0, outerMsg, BLOCK_LEN, innerHash.length);
		return getHash(outerMsg);
	}
	
	
	
	/*---- Private functions ----*/
	
	private static void compress(long[] state, byte[] blocks, int len) {
		if (len < 0 || len % BLOCK_LEN != 0)
			throw new IllegalArgumentException();
		for (int i = 0; i < len; i += BLOCK_LEN) {
			
			// Message schedule
			long[] schedule = new long[80];
			for (int j = 0; j < BLOCK_LEN; j++)
				schedule[j / 8] |= (blocks[i + j] & 0xFFL) << ((7 - j % 8) * 8);
			for (int j = 16; j < 80; j++) {
				schedule[j] = schedule[j-16] + schedule[j-7]
					+ (rotateRight(schedule[j-15],  1) ^ rotateRight(schedule[j-15],  8) ^ (schedule[j-15] >>> 7))
					+ (rotateRight(schedule[j- 2], 19) ^ rotateRight(schedule[j- 2], 61) ^ (schedule[j- 2] >>> 6));
			}
			
			// The 80 rounds
			long a = state[0];
			long b = state[1];
			long c = state[2];
			long d = state[3];
			long e = state[4];
			long f = state[5];
			long g = state[6];
			long h = state[7];
			for (int j = 0; j < 80; j++) {
				long t1 = h + (rotateRight(e, 14) ^ rotateRight(e, 18) ^ rotateRight(e, 41)) + (g ^ (e & (f ^ g))) + ROUND_CONSTANTS[j] + schedule[j];
				long t2 = (rotateRight(a, 28) ^ rotateRight(a, 34) ^ rotateRight(a, 39)) + ((a & (b | c)) | (b & c));
				h = g;
				g = f;
				f = e;
				e = d + t1;
				d = c;
				c = b;
				b = a;
				a = t1 + t2;
			}
			state[0] += a;
			state[1] += b;
			state[2] += c;
			state[3] += d;
			state[4] += e;
			state[5] += f;
			state[6] += g;
			state[7] += h;
		}
	}
	
	
	/*---- Class constants ----*/
	
	private static final long[] ROUND_CONSTANTS = {
		0x428A2F98D728AE22L, 0x7137449123EF65CDL, 0xB5C0FBCFEC4D3B2FL, 0xE9B5DBA58189DBBCL,
		0x3956C25BF348B538L, 0x59F111F1B605D019L, 0x923F82A4AF194F9BL, 0xAB1C5ED5DA6D8118L,
		0xD807AA98A3030242L, 0x12835B0145706FBEL, 0x243185BE4EE4B28CL, 0x550C7DC3D5FFB4E2L,
		0x72BE5D74F27B896FL, 0x80DEB1FE3B1696B1L, 0x9BDC06A725C71235L, 0xC19BF174CF692694L,
		0xE49B69C19EF14AD2L, 0xEFBE4786384F25E3L, 0x0FC19DC68B8CD5B5L, 0x240CA1CC77AC9C65L,
		0x2DE92C6F592B0275L, 0x4A7484AA6EA6E483L, 0x5CB0A9DCBD41FBD4L, 0x76F988DA831153B5L,
		0x983E5152EE66DFABL, 0xA831C66D2DB43210L, 0xB00327C898FB213FL, 0xBF597FC7BEEF0EE4L,
		0xC6E00BF33DA88FC2L, 0xD5A79147930AA725L, 0x06CA6351E003826FL, 0x142929670A0E6E70L,
		0x27B70A8546D22FFCL, 0x2E1B21385C26C926L, 0x4D2C6DFC5AC42AEDL, 0x53380D139D95B3DFL,
		0x650A73548BAF63DEL, 0x766A0ABB3C77B2A8L, 0x81C2C92E47EDAEE6L, 0x92722C851482353BL,
		0xA2BFE8A14CF10364L, 0xA81A664BBC423001L, 0xC24B8B70D0F89791L, 0xC76C51A30654BE30L,
		0xD192E819D6EF5218L, 0xD69906245565A910L, 0xF40E35855771202AL, 0x106AA07032BBD1B8L,
		0x19A4C116B8D2D0C8L, 0x1E376C085141AB53L, 0x2748774CDF8EEB99L, 0x34B0BCB5E19B48A8L,
		0x391C0CB3C5C95A63L, 0x4ED8AA4AE3418ACBL, 0x5B9CCA4F7763E373L, 0x682E6FF3D6B2B8A3L,
		0x748F82EE5DEFB2FCL, 0x78A5636F43172F60L, 0x84C87814A1F0AB72L, 0x8CC702081A6439ECL,
		0x90BEFFFA23631E28L, 0xA4506CEBDE82BDE9L, 0xBEF9A3F7B2C67915L, 0xC67178F2E372532BL,
		0xCA273ECEEA26619CL, 0xD186B8C721C0C207L, 0xEADA7DD6CDE0EB1EL, 0xF57D4F7FEE6ED178L,
		0x06F067AA72176FBAL, 0x0A637DC5A2C898A6L, 0x113F9804BEF90DAEL, 0x1B710B35131C471BL,
		0x28DB77F523047D84L, 0x32CAAB7B40C72493L, 0x3C9EBE0A15C9BEBCL, 0x431D67C49C100D4CL,
		0x4CC5D4BECB3E42B6L, 0x597F299CFC657E2AL, 0x5FCB6FAB3AD6FAECL, 0x6C44198C4A475817L,
	};
	
	
	
	/*---- Miscellaneous ----*/
	
	private Sha512() {}  // Not instantiable
	
}
