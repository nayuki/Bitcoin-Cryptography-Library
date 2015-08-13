/* 
 * Bitcoin cryptography library, copyright (c) Project Nayuki
 * http://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

import static org.junit.Assert.assertArrayEquals;
import java.util.Arrays;
import org.junit.Test;


public final class CurvePointMathTest {
	
	@Test public void testTwice() {
		String[][] cases = {
			{"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"},
			{"e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", "51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922"},
			{"2f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01", "5c4da8a741539949293d082a132d13b4c2e213d6ba5b7617b5da2cb76cbde904"},
			{"e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a", "f7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821"},
			{"d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65", "95038d9d0ae3d5c3b3d6dec9e98380651f760cc364ed819605b3ff1f24106ab9"},
			{"bf23c1542d16eab70b1051eaf832823cfc4c6f1dcdbafd81e37918e6f874ef8b", "5cb3866fc33003737ad928a0ba5392e4c522fc54811e2f784dc37efe66831d9f"},
			{"34ff3be4033f7a06696c3d09f7d1671cbcf55cd700535655647077456769a24e", "5d9d11623a236c553f6619d89832098c55df16c3e8f8b6818491067a73cc2f1a"},
			{"8282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508", "11f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf"},
			{"465370b287a79ff3905a857a9cf918d50adbc968d9e159d0926e2c00ef34a24d", "35e531b38368c082a4af8bdafdeec2c1588e09b215d37a10a2f8fb20b33887f4"},
			{"241febb8e23cbd77d664a18f66ad6240aaec6ecdc813b088d5b901b2e285131f", "513378d9ff94f8d3d6c420bd13981df8cd50fd0fbd0cb5afabb3e66f2750026d"},
		};
		int[] p = CurvePointMath.getBasePoint();
		for (String[] cs : cases) {
			CurvePointMath.twice(p, 0, new int[120], 0);
			CurvePointMath.normalize(p, 0, new int[96], 0);
			assertArrayEquals(toInt256(cs[0]), Arrays.copyOfRange(p, 0, 8));
			assertArrayEquals(toInt256(cs[1]), Arrays.copyOfRange(p, 8, 16));
			assertArrayEquals(INT256_ONE, Arrays.copyOfRange(p, 16, 24));
		}
	}
	
	
	/*---- Helper definitions ----*/
	
	private static int[] toInt256(String s) {
		int[] result = new int[8];
		for (int i = 0; i < 8; i++)
			result[i] = (int)Long.parseLong(s.substring((7 - i) * 8, (8 - i) * 8), 16);
		return result;
	}
	
	
	private static final int[] INT256_ONE = {1, 0, 0, 0, 0, 0, 0, 0};
	
}
