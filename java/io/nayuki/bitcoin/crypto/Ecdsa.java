package io.nayuki.bitcoin.crypto;

import static io.nayuki.bitcoin.crypto.Int256Math.NUM_WORDS;
import java.util.Arrays;


/**
 * Computes an ECDSA signature deterministically. Not instantiable.
 */
public final class Ecdsa {
	
	/*---- Static functions ----*/
	
	// Computes the signature when given the private key, message hash, and random nonce.
	// Returns true if signing was successful (overwhelming probability), or false if a new nonce must be chosen (vanishing probability).
	// The nonce must be in the range [1, CurvePointMath.ORDER). The outputs are unchanged if signing failed.
	// Note: The nonce must be unique, unpredictable, and secret. Otherwise the signature may leak the private key.
	// All successful executions are constant-time with respect to the input values; in order words
	// one successful execution is indistinguishable from another one based on side channel information.
	public static boolean sign(int[] privateKey, Sha256Hash msgHash, int[] nonce, int[] outR, int[] outS) {
		if (privateKey == null || msgHash == null || nonce == null || outR == null || outS == null)
			throw new NullPointerException();
		if (privateKey.length != NUM_WORDS || nonce.length != NUM_WORDS || outR.length != NUM_WORDS || outS.length != NUM_WORDS)
			throw new IllegalArgumentException();
		
		/* 
		 * Pseudocode:
		 *   if (nonce outside range [1, order-1]) return false;
		 *   p = nonce * G;
		 *   r = p.x % order;
		 *   if (r == 0) return false;
		 *   s = nonce^-1 * (msgHash + r * privateKey) % order;
		 *   if (s == 0) return false;
		 *   s = min(s, order - s);
		 */
		
		int[] val = new int[2 * NUM_WORDS + CurvePointMath.POINT_WORDS + 552];  // Temporary scratch space for all values
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
	
	
	// Computes a deterministic nonce based on the HMAC of the message hash with the private key,
	// and then performs ECDSA signing. Returns true iff successful (extremely likely).
	public static boolean signWithHmacNonce(int[] privateKey, Sha256Hash msgHash, int[] outR, int[] outS) {
		if (privateKey == null || msgHash == null || outR == null || outS == null)
			throw new NullPointerException();
		if (privateKey.length != NUM_WORDS || outR.length != NUM_WORDS || outS.length != NUM_WORDS)
			throw new IllegalArgumentException();
		
		byte[] privkeyBytes = Int256Math.uintToBytes(privateKey, 0);
		byte[] msghashBytes = msgHash.toBytes();
		byte[] hmac = Sha256.getHmac(privkeyBytes, msghashBytes).toBytes();
		int[] nonce = new int[8];
		Int256Math.bytesToUint(hmac, nonce, 0);
		return sign(privateKey, msgHash, nonce, outR, outS);
	}
	
	
	
	/*---- Private functions ----*/
	
	// Computes x = (x * y) % CurvePointMath.ORDER. Requires x < CurvePointMath.ORDER.
	// tempOff indexes into the x array, and uses 16 words of temporary space.
	private static void multiplyModOrder(int[] x, int xOff, int[] y, int yOff, int tempOff) {
		/* 
		 * Russian peasant multiplication with modular reduction at each step. Pseudocode:
		 *   copy = x;
		 *   x = 0;
		 *   for (i = 255 .. 0) {
		 *     x = (x * 2) % order;
		 *     if (y.bit[i] == 1)
		 *       x = (x + copy) % order;
		 *   }
		 */
		int modOff  = tempOff + 0 * NUM_WORDS;
		int copyOff = tempOff + 1 * NUM_WORDS;
		System.arraycopy(CurvePointMath.ORDER, 0, x, tempOff, NUM_WORDS);
		System.arraycopy(x, xOff, x, copyOff, NUM_WORDS);
		assert Int256Math.lessThan(x, xOff, modOff) == 1;
		Arrays.fill(x, xOff, xOff + NUM_WORDS, 0);
		
		for (int i = 255; i >= 0; i--) {
			// Multiply by 2
			int c = Int256Math.uintShiftLeft1(x, xOff, xOff);
			Int256Math.uintSubtract(x, xOff, modOff, c | (Int256Math.lessThan(x, xOff, modOff) ^ 1), xOff);
			// Conditionally add 'copy'
			int enable = (y[yOff + (i >>> 5)] >>> (i & 31)) & 1;
			c = Int256Math.uintAdd(x, xOff, copyOff, enable, xOff);
			Int256Math.uintSubtract(x, xOff, modOff, c | (Int256Math.lessThan(x, xOff, modOff) ^ 1), xOff);
			assert Int256Math.lessThan(x, xOff, modOff) == 1;
		}
	}
	
	
	
	/*---- Miscellaneous ----*/
	
	private Ecdsa() {}  // Not instantiable
	
}
