/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package io.nayuki.bitcoin.crypto;

import static io.nayuki.bitcoin.crypto.Int256Math.NUM_WORDS;
import java.util.Arrays;
import java.util.Objects;


/**
 * Performs ECDSA signature generation and verification. Provides just three static functions.
 */
public final class Ecdsa {
	
	/*---- Static functions ----*/
	
	// Computes the signature (deterministically) when given the private key, message hash, and random nonce.
	// Returns true if signing was successful (overwhelming probability), or false if a new nonce must be chosen
	// (vanishing probability). Both privateKey and nonce must be in the range [1, CurvePointMath.ORDER).
	// outR and outS will be in the same range too; their values are assigned iff signing is successful.
	// Note: The nonce must be unique, unpredictable, and secret. Otherwise the signature may leak the private key.
	// All successful executions are constant-time with respect to the input values; in order words
	// one successful execution is indistinguishable from another one based on side channel information.
	public static boolean sign(int[] privateKey, Sha256Hash msgHash, int[] nonce, int[] outR, int[] outS) {
		Objects.requireNonNull(privateKey);
		Objects.requireNonNull(msgHash);
		Objects.requireNonNull(nonce);
		Objects.requireNonNull(outR);
		Objects.requireNonNull(outS);
		if (privateKey.length != NUM_WORDS || nonce.length != NUM_WORDS || outR.length != NUM_WORDS || outS.length != NUM_WORDS)
			throw new IllegalArgumentException();
		
		/* 
		 * Algorithm pseudocode:
		 * if (nonce outside range [1, order-1]) return false
		 * p = nonce * G
		 * r = p.x % order
		 * if (r == 0) return false
		 * s = nonce^-1 * (msgHash + r * privateKey) % order
		 * if (s == 0) return false
		 * s = min(s, order - s)
		 */
		
		int[] val = new int[2 * NUM_WORDS + CurvePointMath.POINT_WORDS + CurvePointMath.MULTIPLY_TEMP_WORDS];  // Temporary scratch space for all values
		int tempOff = 5 * NUM_WORDS;
		int nonceOff = 0 * NUM_WORDS;  // Uint256
		int orderOff = 1 * NUM_WORDS;  // Uint256
		System.arraycopy(nonce, 0, val, nonceOff, NUM_WORDS);
		System.arraycopy(CurvePointMath.ORDER, 0, val, orderOff, NUM_WORDS);
		if (Int256Math.isZero(nonce, 0) == 1 || Int256Math.lessThan(val, nonceOff, orderOff) == 0)
			return false;
		
		int pOff = 2 * NUM_WORDS;  // CurvePoint
		System.arraycopy(CurvePointMath.BASE_POINT, 0, val, pOff, CurvePointMath.POINT_WORDS);
		CurvePointMath.multiply(val, pOff, nonceOff, tempOff);
		CurvePointMath.normalize(val, pOff, tempOff);
		
		int rOff = pOff + CurvePointMath.XCOORD;  // Uint256, aliasing p.x
		Int256Math.uintSubtract(val, rOff, orderOff, Int256Math.lessThan(val, rOff, orderOff) ^ 1, rOff);
		if (Int256Math.isZero(val, rOff) == 1)
			return false;
		assert Int256Math.lessThan(val, rOff, orderOff) == 1;
		
		int sOff = pOff + CurvePointMath.YCOORD;  // Uint256, reuses space
		int zOff = pOff + CurvePointMath.ZCOORD;  // Uint256, reuses space
		System.arraycopy(val, rOff, val, sOff, NUM_WORDS);
		Arrays.fill(val, zOff, zOff + NUM_WORDS, 0);
		Int256Math.bytesToUint(msgHash.toBytes(), val, zOff);
		multiplyModOrder(val, sOff, privateKey, 0, tempOff);
		int carry = Int256Math.uintAdd(val, sOff, zOff, 1, sOff);
		Int256Math.uintSubtract(val, sOff, orderOff, carry | (Int256Math.lessThan(val, sOff, orderOff) ^ 1), sOff);
		
		int kInvOff = zOff;  // Uint256, reuses space
		Int256Math.reciprocal(val, nonceOff, orderOff, kInvOff, tempOff);
		multiplyModOrder(val, sOff, val, kInvOff, tempOff);
		if (Int256Math.isZero(val, sOff) == 1)
			return false;
		
		int negSOff = zOff;  // Uint256, reuses space
		Int256Math.uintSubtract(val, orderOff, sOff, 1, negSOff);
		Int256Math.replace(val, sOff, negSOff, Int256Math.lessThan(val, negSOff, sOff));  // To ensure low S values for BIP 62
		System.arraycopy(val, rOff, outR, 0, NUM_WORDS);
		System.arraycopy(val, sOff, outS, 0, NUM_WORDS);
		return true;
	}
	
	
	// Computes a deterministic nonce based on the HMAC-SHA-256 of the message hash with the private key,
	// and then performs ECDSA signing. Returns true iff signing is successful (with overwhelming probability).
	// This has the same constant-time behavior as sign().
	public static boolean signWithHmacNonce(int[] privateKey, Sha256Hash msgHash, int[] outR, int[] outS) {
		Objects.requireNonNull(privateKey);
		Objects.requireNonNull(msgHash);
		Objects.requireNonNull(outR);
		Objects.requireNonNull(outS);
		if (privateKey.length != NUM_WORDS || outR.length != NUM_WORDS || outS.length != NUM_WORDS)
			throw new IllegalArgumentException();
		
		byte[] privkeyBytes = Int256Math.uintToBytes(privateKey, 0);
		byte[] msghashBytes = msgHash.toBytes();
		byte[] hmac = Sha256.getHmac(privkeyBytes, msghashBytes).toBytes();
		int[] nonce = new int[Int256Math.NUM_WORDS];
		Int256Math.bytesToUint(hmac, nonce, 0);
		return sign(privateKey, msgHash, nonce, outR, outS);
	}
	
	
	// Checks whether the given signature, message, and public key are valid together.
	// publicKey is a normalized CurvePoint, r is a Uint256, and s is a Uint256.
	// This function does not need to be constant-time because all inputs are public.
	public static boolean verify(int[] publicKey, Sha256Hash msgHash, int[] r, int[] s) {
		Objects.requireNonNull(publicKey);
		Objects.requireNonNull(msgHash);
		Objects.requireNonNull(r);
		Objects.requireNonNull(s);
		if (publicKey.length != CurvePointMath.POINT_WORDS || r.length != NUM_WORDS || s.length != NUM_WORDS)
			throw new IllegalArgumentException();
		
		/* 
		 * Algorithm pseudocode:
		 * if (pubKey == zero || !(pubKey is normalized) ||
		 *     !(pubKey on curve) || n * pubKey != zero)
		 *   return false
		 * if (!(0 < r, s < order))
		 *   return false
		 * w = s^-1 % order
		 * u1 = (msgHash * w) % order
		 * u2 = (r * w) % order
		 * p = u1 * G + u2 * pubKey
		 * return r == p.x % order
		 */
		
		int[] val = new int[9 * NUM_WORDS + CurvePointMath.MULTIPLY_TEMP_WORDS];
		int tempOff  = 9 * NUM_WORDS;
		int orderOff = 0 * NUM_WORDS;  // Uint256
		System.arraycopy(CurvePointMath.ORDER, 0, val, orderOff, NUM_WORDS);
		
		int rOff = 1 * NUM_WORDS;  // Uint256
		int sOff = 2 * NUM_WORDS;  // Uint256
		System.arraycopy(r, 0, val, rOff, NUM_WORDS);
		System.arraycopy(s, 0, val, sOff, NUM_WORDS);
		if (    Int256Math.isZero(r, 0) == 1 || Int256Math.lessThan(val, rOff, orderOff) == 0 ||
		        Int256Math.isZero(s, 0) == 1 || Int256Math.lessThan(val, sOff, orderOff) == 0)
			return false;
		
		int qOff   = 3 * NUM_WORDS;  // CurvePoint
		int oneOff = 6 * NUM_WORDS;  // Uint256
		System.arraycopy(publicKey, 0, val, qOff, CurvePointMath.POINT_WORDS);
		System.arraycopy(Int256Math.ONE, 0, val, oneOff, NUM_WORDS);
		if (CurvePointMath.isZero(publicKey, 0) == 1 || Int256Math.equalTo(val, qOff + CurvePointMath.ZCOORD, oneOff) == 0
				|| CurvePointMath.isOnCurve(val, qOff, tempOff) == 0)
			return false;
		CurvePointMath.multiply(val, qOff, orderOff, tempOff);
		if (CurvePointMath.isZero(val, qOff) == 0)
			return false;
		
		int wOff = 2 * NUM_WORDS;  // Uint256, reuses space
		Int256Math.reciprocal(val, sOff, orderOff, wOff, tempOff);
		
		int u1Off = 3 * NUM_WORDS;  // Uint256, reuses space
		int u2Off = 2 * NUM_WORDS;  // Uint256, reuses space
		int zOff  = 4 * NUM_WORDS;  // Uint256, reuses space
		Int256Math.bytesToUint(msgHash.toBytes(), val, zOff);
		System.arraycopy(val, wOff, val, u1Off, NUM_WORDS);
		multiplyModOrder(val, u1Off, val, zOff, tempOff);
		multiplyModOrder(val, u2Off, r, 0, tempOff);
		
		int pOff = 6 * NUM_WORDS;  // CurvePoint, reuses space
		System.arraycopy(CurvePointMath.BASE_POINT, 0, val, pOff, CurvePointMath.POINT_WORDS);
		CurvePointMath.multiply(val, pOff, u1Off, tempOff);
		System.arraycopy(publicKey, 0, val, qOff, CurvePointMath.POINT_WORDS);
		CurvePointMath.multiply(val, qOff, u2Off, tempOff);
		CurvePointMath.add(val, pOff, qOff, tempOff);
		CurvePointMath.normalize(val, pOff, tempOff);
		int reduce = Int256Math.lessThan(val, pOff + CurvePointMath.XCOORD, orderOff) ^ 1;
		Int256Math.uintSubtract(val, pOff + CurvePointMath.XCOORD, orderOff, reduce, pOff + CurvePointMath.XCOORD);
		return Int256Math.equalTo(val, rOff, pOff + CurvePointMath.XCOORD) == 1;
	}
	
	
	
	/*---- Private functions ----*/
	
	// Computes x = (x * y) % CurvePointMath.ORDER. Requires x < CurvePointMath.ORDER, but y is unrestricted.
	// tempOff indexes into the x array, and uses 16 words of temporary space.
	private static void multiplyModOrder(int[] x, int xOff, int[] y, int yOff, int tempOff) {
		/* 
		 * Russian peasant multiplication with modular reduction at each step. Algorithm pseudocode:
		 * z = 0
		 * for (i = 255 .. 0) {
		 *   z = (z * 2) % order
		 *   if (y.bit[i] == 1)
		 *     z = (z + x) % order
		 * }
		 * x = z
		 */
		int modOff = tempOff + 0 * NUM_WORDS;
		int zOff   = tempOff + 1 * NUM_WORDS;
		System.arraycopy(CurvePointMath.ORDER, 0, x, modOff, NUM_WORDS);
		System.arraycopy(Int256Math.ZERO, 0, x, zOff, NUM_WORDS);
		assert Int256Math.lessThan(x, xOff, modOff) == 1;
		
		for (int i = Int256Math.NUM_WORDS * 32 - 1; i >= 0; i--) {
			// Multiply by 2
			int c = Int256Math.uintShiftLeft1(x, zOff, zOff);
			Int256Math.uintSubtract(x, zOff, modOff, c | (Int256Math.lessThan(x, zOff, modOff) ^ 1), zOff);
			// Conditionally add x
			int enable = (y[yOff + (i >>> 5)] >>> (i & 31)) & 1;
			c = Int256Math.uintAdd(x, zOff, xOff, enable, zOff);
			Int256Math.uintSubtract(x, zOff, modOff, c | (Int256Math.lessThan(x, zOff, modOff) ^ 1), zOff);
			assert Int256Math.lessThan(x, zOff, modOff) == 1;
		}
		System.arraycopy(x, zOff, x, xOff, NUM_WORDS);
	}
	
	
	
	/*---- Miscellaneous ----*/
	
	private Ecdsa() {}  // Not instantiable
	
}
