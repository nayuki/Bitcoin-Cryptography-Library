/* 
 * Runnable main program that tests the functionality of class Sha256.
 * 
 * Copyright (c) Project Nayuki
 * http://www.nayuki.io/
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include "Sha256.h"
#include "Sha256Hash.h"


// Data structures
struct TestCase {
	const bool matches;
	const Sha256Hash expectedHash;
	const char *message;
};
struct HmacCase {
	const bool matches;
	const Sha256Hash expectedHash;
	const char *key;
	const char *message;
};


// Remember that all 256-bit hash strings are byte-reversed as per the Bitcoin convention.
int main(int argc, char **argv) {
	// Single SHA-256 hash
	TestCase singleCases[] = {
		// Standard test vectors
		{true, Sha256Hash("55b852781b9995a44c939b64e441ae2724b96f99c8f4fb9a141cfc9842c4b0e3"), ""},
		{true, Sha256Hash("bb48eeaf857780b9724e7c14f8ef86a74ddc239ab331c2facabd1bca128197ca"), "a"},
		{true, Sha256Hash("ad1500f261ff10b49c7a1796a36103b02322ae5dde404141eacf018fbf1678ba"), "abc"},
		{true, Sha256Hash("50b63c393d41a1a3efc4fb48339e505bad0c55e1b4b5eaeb4ee123cf556f84f7"), "message digest"},
		{true, Sha256Hash("738bf1daf232d89e8dfc51cf1862315e52c9667c44d1fa1e2faed693df80c471"), "abcdefghijklmnopqrstuvwxyz"},
		{true, Sha256Hash("c106db19d4edecf66721ff6459e43ca339603e0c9326c0e5b83806d2616a8d24"), "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
		// Mismatches caused by slight perturbations
		{false, Sha256Hash("55b852781b9995a44c939b64e441ae2724b96f79c8f4fb9a141cfc9842c4b0e3"), ""},
		{false, Sha256Hash("bb48eeaf857780b9724e7c14f8ef86a74ddc239ab331c2facabd1bca128197ca"), "b"},
		// Random printable-ASCII test vectors of increasing length
		{true, Sha256Hash("12519f99de14034a3aa90d64469e307cae43c5d0d0182c21f92032e922e07339"), "-"},
		{true, Sha256Hash("58f4584d67f9ffcedb92f76e386e44d5ecd97af3eee0d57712d0b8893831f5cd"), "O4"},
		{true, Sha256Hash("c69b69fd9c933f0f6fa6a41fa2f9e0830e88f27126230365c2446c9cb1c236c5"), "Qz5"},
		{true, Sha256Hash("109da8d29f0d36355d618ef7f05170c5ff69e32b0f7a8f6efa2714dd1f1a7151"), "Y$h/"},
		{true, Sha256Hash("82430afd2a2ef8f7167a75a4a2dfcab7573ea754e870de8c71a65520f78b9a66"), "p(kaX"},
		{true, Sha256Hash("05abeeff1d8bd80ca018415e262dcc2e5cedd54109a11eadc6f6e7d4f48f120d"), "\"i?#/S"},
		{true, Sha256Hash("ccabddbd2f828fc5bfa15651a60fdc22e8c6ec1070acc9a32a1dd7fffbb5c68a"), ";C7zRLL"},
		{true, Sha256Hash("74a83c377597b3f45d6698a06d1ba3a3960252469c5cc20fd34cba2f2ee13be9"), "1eZ0a*(u"},
		{true, Sha256Hash("21c2dc51434674770786628e9ec59e2341351f9193a14b9661a8f8a5b25d9079"), "4?P[@+J5D"},
		{true, Sha256Hash("c61169091b4d50105b91a89b73768b994373ab655f8565f10a3b6974dfc1edb0"), "G]ipN8[69O"},
		{true, Sha256Hash("c02cc8860e8562ce09bdde7a9f091d364d6b8d6410915b0c119c4d7f8da00084"), "jWhXp?l)0Ws"},
		{true, Sha256Hash("efbdf767e0d5d11f73a97b5a554a142511649c7e78197ddc40e5dc1f55c9bcf6"), "U!0WFh~5J=,4"},
		{true, Sha256Hash("fba0b40d9264d56ec7a4c302fee71702d9a2cdc7d2f241f77cd2a7e496b279ec"), "m67V.]u6]%!`N"},
		{true, Sha256Hash("c9d8cdd32502f9123f0fc9d932b16f9113d633fabe7387c52a52689d1c3be7a4"), "TbS'R]jANh?pM$"},
		{true, Sha256Hash("d14003a6cb0039e91f1d8935648e9837be927fcf06acda64eac3a3d16ed5fd09"), "KbGSWuU%6FNq xR"},
		{true, Sha256Hash("b6d9677d4cfc14ec96f964810f1d0f22638fdab4aee0b0e681824792878b5370"), "!lqe]~UJsqb)Li5t"},
		{true, Sha256Hash("63a676d1304adeb737450a00153e44a6b144e4bbc19f0f22bae97ad4b1811592"), "L^O%CcsTCgH%q!Ct*"},
		{true, Sha256Hash("a55870e9a6fbb684d21602407033ad4074ef215f86adc48424a69f56c3918e26"), "O!Vx(?<Gy: j=EA`^%"},
		{true, Sha256Hash("99deaacd61a2894bbfcc101e02ddd811e693617b40057b2ca002c959872ff262"), "z0L|?AG$>3L<)xP6I%\""},
		{true, Sha256Hash("c73e9bd7719dc2ad90b2069325c5626e039faa8dfdfb5e58d2a033efcf692a03"), "G(UOs.5lvi(xR;+OU\"/{"},
		{true, Sha256Hash("6f0188be07910e8657065b7189ef5d6dbd8c7d680f71bc0ba6235559e64d957b"), "9\"/m921Iwl[.<)toSRk5g"},
		{true, Sha256Hash("1e3d608223c332142f0dee8cb68183b83bd59bf12d2b5be332f918794f6cc9a8"), "zYoz{w@8],,9@q6n?!m/_ "},
		{true, Sha256Hash("3f2888e93a10ebd7df7af407f9eb2ce33697066b17b20298a4bd0c0a8600ecfb"), "*Kn|.@jG{(mxNO{L!gLZzr?"},
		{true, Sha256Hash("a6dbd41504f785e88b5682746efa97c4894a2d1c13980013b80103aaae1293b6"), "hC9E2&bbEg4hO%2\"<|Q^\"`&r"},
		{true, Sha256Hash("8fd5cdf9073f314889b58113557ed822ccf0803faae3409ce036fd7d74f49ca0"), "<N<?~Wx?jqh+[\"63(:'82Ch5O"},
		{true, Sha256Hash("d3180b726a47f8e4ec466a79f3c5b4ea2160496276e0027e2660a1980480280e"), "H@0{\\JEBym}/T0H#gz:2f_w|aP"},
		{true, Sha256Hash("8f25f061c2e0f2a7f0abd8a16017168a6be5271dfbe24987df830c99053c8e3a"), "{Zw4fe6Eieg#+}H%D[Cb(_]0=0M"},
		{true, Sha256Hash("f9225faaf43d338f93a2d8e932a1e423c270aa83e221ed97f28c0e5a0d166ebc"), "hyLGQh3_K|9pgqxg{X?|CYY_|h,$"},
		{true, Sha256Hash("9f7fe14ae87e3bcf46d482665c062378e32cb42c410a5f3361ddec11e09d8105"), "GT;\"&%s{ae7h,#6*ea1\\~87c7{=:O"},
		{true, Sha256Hash("66cec32f20b76edc8af4f83629ef3a7afa0f7fec00c7e889b2d4aeafed90cb3a"), "0GhILn%$~D(TuHA\"#QK`9F=y?t6mbm"},
		{true, Sha256Hash("62a4c56bc2c2ea5821c323431b4a4eabf309896285505c68016cb6434731d037"), "hSbJE 8gA&_Jz]B&'_b3R;m*!N}dlE]"},
		{true, Sha256Hash("cedf17b4ad93419b7b7db695b72b0d4a55d5cfe89241e699898c32ce13670e18"), "EgM%B~rQv2~EkE7+ 3`MBM6j5Zp>*TwO"},
		{true, Sha256Hash("ced452ee980d313c1c483ccb95153b27606c1fd4060d015d99e52eaa8cfc76e5"), "orf=wMzQ/|V$Q;ZnYi*)2VpL<\",dB|/s#"},
		{true, Sha256Hash("3be75c942520147c75e3c01fc6a03db9cdb3efda8f783ef769c6e992f82534f8"), "k<d}Uy:+%JYHr4Mv1lYhpIUUS?=-dwW45!"},
		{true, Sha256Hash("c9a6e47a69a0cbc1b5b129209d9187959dd0f8d5633db27080486057fd684063"), "c-EB00tL'=TQ@i$b6s@_aI&fICA80TUI,BQ"},
		{true, Sha256Hash("84d31a55a61cb4b9e9ebb5e4f851a58e4c28cec34b39e48e7c27229c82ae5567"), "pBC3Zeck.|Yi571V`g(SJf=/R<)\"ux;z:XtG"},
		{true, Sha256Hash("5f254a802579fac2255123e69cb711270acea1eb6e5c2cae0f014e0361ebd8cc"), "Ai5[N[s v?CL^$H92q6z=^\"G?}e$8cn<qn5gO"},
		{true, Sha256Hash("a84edbe255c7abb69c66961aef61e20721bb974bb2b6cb3d7be33adb0a5bc9ee"), "d27eE1x *|3,H`8mtu*!DmX~wO}*:vW,k~d}'y"},
		{true, Sha256Hash("1afa1dd2965650d03ef935a1a0617794baddfffedf2bd26cd6a75816492c5e8b"), "*Y1HvEQ^jB131g?Da~g$O,E|rc7AVR$H9laT*7d"},
		{true, Sha256Hash("69dd41ef45671445e0af3d1389152cc681de49bdbc593f96b50c879507ad3ad5"), "2/6<-xS4E)1:p<~!,.^.>AX9AyaAVbP3/k>MU88A"},
		{true, Sha256Hash("b92dacb6a360de574bebb8e22315d95d9d79aea5d895f8a6b475cf8979e7bb14"), "%,-v7y@\\T+`^=ais olL8\"7;]kUc{.p'$*iRyYyEt"},
		{true, Sha256Hash("e3c5c024e5723d11cc360f368ad0606432f6fd5f469805fd2c4df81e627e9b3f"), "HGqueCu(AZV:;R+h eE5*VX``jRn1>Y1>PVO.;ai7K"},
		{true, Sha256Hash("1b9b11f5268027a26e84402be0e18f54c44d262c61238dd376bd7b093e64e236"), "+f5d0;l;~/YPaU{T#,81IgtLzPNbR}@p)8S O>*rFOm"},
		{true, Sha256Hash("3b07ec8c0419a362a8fd7e02c450bf67b1e3f1dccef77dd9f20751936fd64917"), "H$T-S.9H(nI~b5{}a3,_0f4Bk#zEh5D3Bhii`@qZ*X*)"},
		{true, Sha256Hash("75d294bacf2383c0a1b034f5a4aaafdd44a92fc0f71f53cd4f6ed9478d2e4e02"), "l:EE?=fruAeU\\%jl~1<N_lH6ibQUx*0D\\k\"#`cO\"(xTI_"},
		{true, Sha256Hash("8db849243e2db44b94cdd59c7a8e6e76d4f7324906ce815f2193bdb5098aece0"), "l S$@Ay'*qj#6l_YU98pS#zZb,p}MWb-&QD}ZfK6z~nR0@"},
		{true, Sha256Hash("21f4d945725352aaa2b4c20254a9b2c68fa9eae5461d3c6b773b745956457292"), "Be*]CTIac|<4IsEbKL*;n=7nSU(HME=TL_F3&[3e=%Jmq}p"},
		{true, Sha256Hash("029cebfdcdfbafc06390cadd54a93472e49211adde0d4dab694b05bedad2813e"), "V'(O@sMxFCK4G]fwG8PZ9&+MqI(})jN!hy8biBBN7XE*Fb}\""},
		{true, Sha256Hash("ac8f0a65812c01c9fe7fe69aa8de31da4683ed2ec1c74497643febfe4fc2b00f"), "a6!-B}\\oT)W{G[YZJg9~5d?]2m`G;>>EqR-jl6g*h0a!;nfA="},
		{true, Sha256Hash("bae22197cd51e5572d6a2780b8447844667fb35b1c2bc227df93521f19f274b4"), "\"sFIX?Jfm<g5o:oMvEwrffHWL$~qQ$d1ZyFIg/<0d5sBs[;k']"},
		{true, Sha256Hash("8ce416fd0e24ad4b5d0af0465fc45a52c0d7915026470008e79751add026058b"), "[nT;M; G7\"^m~vREg((2FGD7DWR*'T(T%,b^7IRv5u/u?$BHKXh"},
		{true, Sha256Hash("2d942b655215d095d6314f0515c9978056eda583437580d28cfd405b5ef135c1"), "[o#v&H$@?rgcD6.lZXmq: M9'})v1'##2wv>i:Z[dfQAAY~{tQ%)"},
		{true, Sha256Hash("1e94945f3e6c18897a83abb12aae83cc3f29d73322a3a378a55e9de9a8211208"), "ii!.\\JgDf_{O\">~2OI.Jg6*YW(/I)f@+'!:^*yaa| WtH(th-ywrG"},
		{true, Sha256Hash("845e6b3330590c34b21e536de85e823f679e38acd7b637eace8d10f82aa588a1"), "Qp~`wM$euEsC,j`RJ$MLX1QXqL'UsB`` q0X!^^w5;Y8CSM}Ueil%1"},
		{true, Sha256Hash("f0075098ac874946f513d579acc6fdb48b58a3b81bf47cf33011fafb816f1d23"), "hoqgC#/ .Hy*<iU&v{9(Bak5;EdG,]!/#=f9{Dok)SpU9*k<eqzv$0!"},
		{true, Sha256Hash("138ebb0fd5d5fe1f718508ec392b8beaaa80d2985adce0a3fe92159d4e599dfd"), "^+\"agIi)QL[-i1F<e$s>r!;A7dbK(Q cMk_oHi->K.Fm5PAFl\\._RB`>"},
		{true, Sha256Hash("27a99b0ee8b70e4af2c56795aaff7f162bc4296ea9e14b3546885c19f3c0594f"), "A8:'hG>=N)-~P}|BFo!6lH5TSyZ%pb',/'^Z1h'+8l40WDt^fY=a|^lfN"},
		{true, Sha256Hash("42546ce891afe745cbd4b7e1cb0d5b2e002d22c15702c859bddb511d539034c4"), "myS$}g+g1CjA-o=?Je(>|sp/ld+[bnQoWsMMO.w6q][cp#fMH%g401+_)E"},
		{true, Sha256Hash("62285bfb2057057a709f47b54f4bfd3d79bbe75605e19df86df6e56b65611539"), "UJIXtIC[qOKBF]t%gS\\6L73\"-}#Qh[V fhj>Tv8Q%32f|x0J!GNOUt4Q_0B"},
		{true, Sha256Hash("8b2df4395442b5625fa5887d9717a8b45181967414ac15ad9558702fbc9a84d1"), "o3cR\"wt8G7ebeMd8nG[{y8>%gOdWtAsqD?|2fACx-ld5R:^ILx(i?E!R?Dv>"},
		{true, Sha256Hash("6dbf9e47237b086a98418ff5716a62945009a448ece9043b278d162c6bd89a5e"), "9Bj_Uvj'.\\ fH92?W`SG,5lduHy19>P?hUuldA'4ymdCe.BJljDq$ '[c{P^Q"},
		{true, Sha256Hash("53f99510cc9b28bed40bfb9ca97d3b0c8326dee2e465526ae5025aeb5ee6ff56"), "%U9##V<M*!,~R@Ru1sL06:NL1Oflz&,qgHY^\\ABzl<EvksI?O9U3T=Dg&rOQ0;"},
		{true, Sha256Hash("4f9b12a197cba685c72db9007cb22fb7d976c94488b6882141ea9f4783398118"), "MPTd8\\7V#+@UziCgC1)6+c5#_))Hd'.T~'ym(f\\hYg'4V-eA<,6mkDFPP+^,|Qx"},
		{true, Sha256Hash("5a75c798d14a1f608303cc6c206fcf87ed460246e144813efbd75660198dac76"), "snIqsB*`CK}#ApzIf1M@wJ9q5XjY1/2-7_wc;uW_$})2KhUM@rZrTuxQF;<R<Tn$"},
		{true, Sha256Hash("8f0b250d4096a8fabb5f982a4ee849ecd36bd249f1d0702f26b04c35bb32a5ed"), "1.;7Sk T\"^JP~]XwjR-FqLhYg0PHMT.r`^/X<Vd,N/Gii1GQk(G|}NyI3Y3(71$lg"},
		{true, Sha256Hash("8cb2a98d578819eb6f8f148b033bea781447f33fa2833d45926f6871d819649f"), "+n/t}U?r>d0wZh*fi5p6W= %B&>zR=bVE^az2U`Sp0B`yf/M$Z!*rMKvco|#x$uLA."},
		{true, Sha256Hash("dad54ad1352771c5e967961aff9e73bbf97bd02e070a311383536c838d458940"), ")n%=%Qt#Z2mSw-5:'^-dYQP|abssfq>U}y4(f$%<B^?)&I44G\"[Ku\\d-T@=\\c14orS@"},
		{true, Sha256Hash("de972098e745e2aa57988bad8c419eb13a519cffb4e594fb0d180b089cc0e3d1"), "oj{dzNZz~fH6IR{@g-)v',KxJ/_|zFm4H<SLSdC{yx%QFlX)<`6MKjykq@70YdNe#WtS"},
		{true, Sha256Hash("56e5a4a44b2bad66d5b3a6de82f4a65d31c4f2f7dbc37903b94c49e451c2f7c2"), "yvs,PKEiYma#+lM`L)!.\\`bx%lWm|7pdeM90e;mX)x9n5b 5>nfcQ*'/jNNU,Gu/kw^w6"},
		{true, Sha256Hash("66b4661774b576f55813d33f2611136584597629ab9994dee3bdcc7fb94253bd"), "]/N}Nsj:b^nmgtLh}))`S-iZE!DL5jfU1:5og|%Qv\\GYE_Q?[=H48b$#9w&K2I!0YS2*G/"},
		{true, Sha256Hash("3b49d3be358dfad8b2424a0c9473dd5cd0379585d61bec192900e7c1e25e1227"), "UZ5K^m+j 7K@p`nd~EW3V{,\\=Ceb](ANDRO}Sg8OSi!bv?|KEP,Ax=e|aC1<uMz<\"CPkY>\""},
		{true, Sha256Hash("f1ff461e6a85eb561037fc77df9ff414e14a00f037ef01f012d4870d6e10aacf"), "]nTJ/de2'*amCCD?4i,Ia-sgTPHY]%_eWo%~(ND0OLm2+tdBxA\\`]k'*,iA*uZ4|^t5g,?UN"},
		{true, Sha256Hash("f51908f5901b48b53d69f5753d15fcc21d30e52ecefa5f3d6371ed6988f04406"), "TDKQKs0>=G\\1?4@?.O8TTz0Z6m{o:Q%+Z#g{cFck*8K`ftnLB]Z%T,J.=~i'ah}$E+H+$3`9r"},
		{true, Sha256Hash("9e5b2b03920a11cbbaa863477dea9445bc0bd0bb03f98234779a570a5add4d9b"), "U'tHcy*pHr2^[.k [Ah7Iv&{sEVwH2F#u1xmNGW2)/A>*cC&X7`3;VCkw[0;Zd[Z^0B*_[_mYx"},
		{true, Sha256Hash("5af612c1dfa1a843856b3be7eb32a7fd6a5f5259ebbbf747f8b853bf0e73c271"), ">;1!4wFLCeqBPaznHY}DF}P2v80.6:'#1eUL1<Z\"GD$X.B^CxRrBP?E96,A@.gxfK}O)2Vc\"87V"},
		{true, Sha256Hash("808b7845b099932f258213339f2eddba791852fdb5315a982feb9a14e5fdab86"), "9JO_]J~ xAgG;NfOZVp6Z)Qw#'vxcau2(HOw]@YK+NQ$}D806 $Q#b^n/z?]7%1id2-N52u)XOs*"},
		{true, Sha256Hash("61bc52b41afde4e2ca2f198b2b4ded51b093f89554aabf453775545761be0a37"), ".ucfBmy!{jXL:Sa*W_`z'+-gWC`%\"24J.dDJ,E#(1[8q;MX?r`>&wLKC6vA?HFpdEpC-L1\"HyCE[@"},
		{true, Sha256Hash("ad5c13afd04977b42737e34406daa7cde5f41f72ff0c094e790c8c9e99377c60"), "Zd}x::j^~bj)n .;cbvRw&xi9.VA, u\\a)axuWv,&=A$Kf5V9FKcJkJlsE\\h}Br72xWgsvN{5h\"Rz1"},
		{true, Sha256Hash("ddbb79112192d0e9efb810e993b8edd0376359b6e09938358f40a1a7582edb3f"), "FLv&`nP5\\q&cLTAHE#J\\M9{QZ`ynI_nH%iIFd>35_5guv4Rb_gwTJRt_fapg{k?_ABF{2<`tWaG1yip"},
		{true, Sha256Hash("87a47bebe1ea0e888432eda50af75187108f40a022d19700c1956d852520a83f"), ",RZ0pEx4FKS(eG5#V>^^C=*9H't3fDK6DHj7]J'|EtMlw&;;unm*5BYbM'.n5!56L`Wz`m8gDz oHC:>"},
		{true, Sha256Hash("05d9e0ec730a0b3e95e2293adbce329a58bf8b40fd1d3d521c02805c0c15a7e7"), "IrK{1@)P,Ymvs.{'hpW0/<sD*o0}ETU?oH6AU)x18O?uBcLFHQ/KAB\\oie[giYz)p9_!NFQ}5Bv-@I-d,"},
		{true, Sha256Hash("289ebbfa6b725683007c1a51e7575a9284baf99a74c8329faddc759996d08608"), "(M\"|IiWs\\Y\\}HvwZ57*-1^gUbpD54l`KO1)ci=Htwt.5!}wsf1;d-o\\F[(tv(MC[G[<Pg/zaD9mOOpD[5a"},
		{true, Sha256Hash("3052c44193d6b700270385575bc497c1a518a4a28542bfb5ee644f77de70b327"), "a/cmlQ6cAMJgo-VvKtG@:$_I%W{9D,^36ghyGFy|B\"kC&#@+pu\"P4meYaEub8,E!{G3akDp;BHv>E,!qILh"},
		{true, Sha256Hash("e6eab879fe3b40edfbee7d19e06db1f87dced1a4207210dddc957b261a6d28c1"), "3>qHD5>aN1Zv<KOj\"eAv~z|M!@2,'bRP? vou6bJWP'T#X1d*X/Oxva[1:M4^bfD2:~;W<^Tg?6SzJZd 2/e"},
		{true, Sha256Hash("95495148da645dde83869bca4fdc6ad86cfec3a3c792d299fcc2516af6335727"), "o26R9s1Ci9.>7&+au5$cLmm5#ymm[rnT6nL?CK_Ibo@/As'!Oe'V~}`mJy<SqXcl11uJuV(^CZx|{;k/n?zpr"},
		{true, Sha256Hash("bddb86d4fbe84489ffb63f0f3e7d814b180a20ed5ec34a01e0506600f9b74ce6"), "PMrX2]fs0pr^oF;03dA:Gu=!.Tp~Yf<{X^Dj#~'OMz0.a$]ti#UH:3MlX`\\f8uC%rp.`={\"AmdAee6>h8`=Iaw"},
		{true, Sha256Hash("3b27ee392836476fde5fb1aea1a40015562f29bbfcfcb5bf8b01859439936f3c"), " rfBW.K6$<41n~(Yurd%d|e?CqV{~o(+F=8G@5Y9?PI4S6oOwb]?MF0g*P%[6*@_c2\\P=Gb44\"0[McsO4UdPz^4"},
		{true, Sha256Hash("5437e139972a905a75b7a4d04de8ed08b534777377e10a9b214294e2c4d6eca8"), "zE,&v|667MR;'VOBkB&!6Dn`>~[-[L(PR, <+z9&fKLe4l|1=&dnQvVSO\\Rx`zI#:CEHnJQBc,8pqG4JXkR\\bknx"},
		{true, Sha256Hash("f8e61bbcace1d174b5b5fd9dfcb5cb1e01fcd3a045b15062ed8ac56be79eee81"), "{c6{!4ova({^j#vokDdk%)D2M?Gfh @UZFDE;s15L8;`l04X3MQ+,6y(I8[^OANqVR1x,Vf?W#K+)(*rl88\"Y?jGw"},
		{true, Sha256Hash("26d36f4091747fa368b4d501d2cef0eaf37ca34562642d0d41c85e87af21680a"), "LkA%jnR)Y/Wv=Aa/mMQ\"P^<s}H#j'm:n=\\uwq|/\\2LWxPq0^'+a?akuds'Ye0!_4p&5cU,N1x:pB_9\\t$^+j<W#l|6"},
		{true, Sha256Hash("6c7358e175a0dab4f47a5b5f0299fd65dbee19d46ef6a07124484ff94516dcf6"), "B4e[x=mmWA4LG(pj|-J?-tD\"##F7)F'\\;~Mnc{#-P$j.n& !(LSU?r?%6IQr%)4FkTWR!z\"h];$;+b+ M~NTAz(9VFv"},
		{true, Sha256Hash("96d9800d4caf4b28b89cf0fca11b3493d8784428d9a6cb9e083ca989920e69ab"), "]w%e&R'h4&Gp&dx3868z^`*uXN( LH`\\`u9^0x!6NTr'2[,uVnr.ua^$vMcx|F:,dO,K+{:Ceyc.xt(\"jp~ZO8^i;W'l"},
		{true, Sha256Hash("6fcc499431ba24c8248500846242486eae9c085b55df0660803cd4ce53a68be1"), "#IB7G;z[gC``_Kn}3IXr<G}\"s4JGWuV(kp/`U4C't*jgS`:zKNWt\"{uUWN*o{Y5n-YHq8H:+49L'NJ~0w}+F_?a-]auM{"},
		{true, Sha256Hash("f42c1c1afb621e5501624cca52a48a42b512e81279b1ab4f9388949ecbaf689a"), "*=V-Ju+8Zbz@Fg'rm]s-0^F-yrveLYZ~S*w257srzjPNK-Ef>;m)uuG*z9X5v2}}>Ci.RbU|gNSHgn=jO~DRIr=fc{JjX{"},
		{true, Sha256Hash("970ae595ce90fe53048ccedde023fa56ec467a5ea709f4b03a595cd11060a229"), "N']+.M+SdX8#z\"#?@t(?;<T?i/#KZf>F]hJ,D?W?(@,/RatubO8w;\"$Yh8l7vBx%+|QEw W7Tr@9?B`^Ap^o}wf'+#'r+?h"},
		{true, Sha256Hash("4ebb13a3a5380c8a370a6790a06a67b11ebe062c66b8cf6733bdf274906faa42"), "-n\\g58b\"%/s/S\\-\"0%;=bAqRrc*KTImxBt$QZU7pNKc{A)49<{ ,);\\?Rf!\"FBpOeMAN|#-it5Qomr~\\3J%Gi#h/efqPREI "},
		{true, Sha256Hash("df1163ce27bed691ed01709063db5a9d88738b1b8d3dc949e81121bf4c0c3d2a"), "Fw:4:d]VAB[!yS#ai?>Q6IL)sD!.'4n0NZk2sJfHoMz[Jh(QFMKZv[3`mO!NhpLy)zrUkkx1:),a%p#=a{+g4~A} Ryj#%nER"},
		{true, Sha256Hash("5f5684144d37a7c1c9ae7839915a8e423acdcf196f17c805dbb38c80a2d97066"), "-SAZekEn.7!<'0OMX(u\"mbj~y{XXk,^sE;eWaQjw3/o'\"b/.|Jn?z@Jucnhuf{THUB['B+ZUb @1ljult *;D$PIA]'zQ9kS|;"},
		{true, Sha256Hash("5c88a9dd0dba90c14fe112f2afacf23b8dd0f067e5b96f1923b58dc588980602"), "d9);3|=p4|;J:8yZmtKS_IA6Q0$Xe~-&${Fl|g,'Ul($BoC!^Ee?aL71No=aD)U;sE_i'F\"fFc,G>_!>yO9 Y|)Q(5`Eemfs<1Y"},
		{true, Sha256Hash("57e147092652f6310b349da857a0a04fa5a81c3ff6b6c147b96053276fad2808"), "&tg\\?OjxC2pKN8k5p%3U9b'Pn`0WTGk@#ZKRAm!(&](yO})y]A{sA2=jr:~/w5UasX5-DD~y[#e((#b9hkU!^9QZy<y[k3PRp`]`"},
		{true, Sha256Hash("f195a1b8142afb88612e895d6f2b7a9c7a5307354143208aa3ba6347a0b7b5fb"), "|//>o=*M`%,yhL\\A:92\\BQyo*NK4.Y hB7??W-Y\\:dKi&k3(4e+%nQ0uXHrX&R':B+&E;3+[RSH&XG_Bna_7,#,qQXWKc(R00Gbo4"},
		{true, Sha256Hash("8a26dd0a05703b61c350b0425218eb6fd255ac344e675790ff98617c4e45bd28"), "$-}9cDBZ=OO&cz w]lp^)hM\"ZuS^juNBOX7`VOX#G9QjgSAth{->t8eG2|}M6)5N|?6'sxY=]\"QBGb>d}@]vb\"jlh1<x/[02_;7wof"},
		{true, Sha256Hash("3342e0dba1804fc0354ecf9fdf038b8e895fdb6bafccad5649bee6f4fec77f52"), "E<.\\rm!3cS|%S},rTc/+5Yzu#!1w5U\\oZi}5!->w4{}'Xg[x!EdY<9Vm!1Qb/1QR#.BWc&&|@T pD!%GeQN7v)j\"I(ci($l>;i{MVU+"},
		{true, Sha256Hash("38ab1076cbc6cf480a876ea97ef5d0b8153ff37f03c88082bd099c4ec1a0daa2"), "r% PRU{.'\":0,/+EU7|X2nf_d(u(K>76xJ7TLF4?-j[!>k=PG+tfHo\"\\c'RDfu' g%Omy[>wuWpO/4~'dU$N7]m\\`|(Ku!?0Y?BVatL("},
		{true, Sha256Hash("ff399b076029580b15b98c6aab415ad0368516277dcc6c46599737699be482e2"), "E#~g,KAstGfhoDa5s-s;F5xU0i,1 gOv1D]\"Ykd2APypljIG`cMmbtPSt@nR+*eB6\\'f@O@V&ER1Ds8f:(R_i~!RmG99onN.beKNFA,J:"},
		{true, Sha256Hash("dca172a9c1fc860fc4db69a2ee2063407709e9df94b3e505f8afa17180ae271a"), "XGOT]u7#Q&L@;Pf^!Mpn\",gi>O^K$U+Bw`?w0ma?MuH!/S#m/&KkutHZm1+l|S:L>oU,[, k,yiA\"Eh|**22Jo#^~wT1vbXf2W}53+A8E9"},
		{true, Sha256Hash("17993bb536779aa26d48343d4926fd0c0fdef240e8495ccaee875cc3318d82f8"), " gE<\\aDfZF,3bFw2\":J>rh!.}cW@rLu+!S`KlZvUe?]lh&{-p2xB>1f\\wYE/Hg6Hl/ew$D.xT6Oc.kT[2ei5y.i?SE?K{hkm%SoAge:S={f"},
		{true, Sha256Hash("ec4e5bc8e25d3d3f2dbb93388dd100dca2294268f2cadc9e19ebc159d45c8fc0"), "^3GL>rL\"WAHS1\\4$e@)\"}Xn2@-? '\\osD@dQ9J6?hF0SPz+cSeANRMm'c \"X($qC{rrPu?tkJj+6/32y035t?9Yg|M$$~eJkuCN*ySJR-3*%"},
		{true, Sha256Hash("5dfeb92ee1dde7c86c72c36f6d36bc960d3ac0f7b0ea9b2e3dc3465ba670dbdb"), "VP*N#`!6o;jp)s%4<4I]3052,9~|rpL>Z862[^qd<'&V:'Sz&Y:i.J]r%]-N9)T?UfNJjL\"\\{]B6G;@pQGe86<+o<d;z&Y7F,M#A?(M%Z89]e"},
		{true, Sha256Hash("300cb029a81f0f5049e81f4239fc22f3a981d7f068b55d0e333ba44a883dafe3"), "s/E^J/UD732KvxFdb=dd/@Y=sR}aLHmtSf]p!kJ54/0mP0{\"`UHpaHMX6Y` qPY@1M}xT7Pj4kC,XGZk<e^0^$^5]@>Vz>,\"pJNQFZ],[,I&x0"},
		{true, Sha256Hash("f14315e3de249c4916aafe9897f8273a74f5f2f0d87542c5bf5d95e038f29df3"), "{n}OCeKt|@x|pv9mt5p&dl/_N5lb3'a$d8#{~KtmZ7cEV1pr'_H[LCP;{V:iWouj)(W59{jgvY-2GQ(2uT18*Tq2$2zJO~cBz.J]H\\9)3PgB:i\\"},
		{true, Sha256Hash("c4b14e1b490ff511c928baf324f797db204d418c01e0988ba1cdea3892147d8a"), "3b_QU(G3{mh+x7^P|x+4!c5&w^HVgZ>D91<:Q(#|\\3kS%qXBmU-)Ov7`Lsf=HD4%9qF^mg`L$C/{vjP}@j{T)u'ZBIX[C0RdOcdxYH@bV?8nR{bo"},
		{true, Sha256Hash("586f36f94af92e9ddc3812870997d477f6ef0873b4ccaf3d776304fd29c43678"), "5XCtj\\iNsU8PDBLb\"v4OTl4iMVQd<nOCM9o{H_7e,oP3dIMGY=*M^6%gU0sTl{X#i*iBZxDny&[7ecEp TKh9Eta=C<|lu2r[#m~a%s]OzGEMt3UV"},
		{true, Sha256Hash("33704360941e55a8a32a66e9e2bf7d196c5537d9ab69a01c5c10c9705c28bc4b"), "8;{>`qwjLl9ic+[HafvW%Tz=L[_bmy=?yRWT_0Odna|L5|+R#m/TdvT;(u&Sq1{'qSbM{Cp~e*r @2Cq^?W,K0HnDe_6Q*#tJ'X(:[P!{Q\"b)fh2Z<"},
		{true, Sha256Hash("e1590ccb24a2e156bbdddfecc2da94989b41b3451b8115876131642e2636d053"), "]D~Xh4964^PwE#I&jB=u_Lxm7qG{F>m%N\"I3wI|GJ#k\\I,zg^!n=\\H\\c2{#}</E(=Fo[:rP)=ZcI^cI6y|K1p#WQvB-5[LZI. G7\\'^s8>=zFeUd5HS"},
		{true, Sha256Hash("63db933b46088190cdb36d0e9b82d32fa8aa3c626eb85afd00b2d071a5f0207c"), "qM;hZ^Q<4l,5EOaV3Ob6`,[)&k6\\ibY+jE&l[&xxi2>^Z}Mymj0K=^w8*~>4=C3bQ4vn9^ \\J1y+--yWh'{Av:n[D:~vu^Ww6Wv|Kh%_g.VE5\\o;(HDq"},
		{true, Sha256Hash("0f1bb25a70ceee0a6326d9296626dda0cee8cb231b4d58709ec96849a410293f"), ";0%IFh)EPr$<E*mo[96RFq$/F@?@N/SZYxUtB9GVC vgZHiKwQ7~`$aXYELRmTf{:|3%MF_vuU))hvm4%L(`'[6FxE8O JKon$}=J68^8d5}y]5<p`xzY"},
		{true, Sha256Hash("ef50f7d7434fde29c4b1f0afab4f6e857b9106df32b4236b3ab3dcdb6318ab6d"), "ghT&.ix!&BT9rh>qEzBs#[6C$'5N,]dhzU=G#>7&D(L4^n6[Dz@czk!5-jC7|GY]2OnT*)v6Ep7(k[6K(?@\\aaCwW`1'7a3]<[DM#2w\\CJwiodi~[_D}n%"},
		{true, Sha256Hash("a102bbcabd9576d4ed65c25c693a907825c459ad37341877734c6ff1bfbae55f"), ">q<DS'&H5(*A.4MkHI2Y}k0s1AO\\iD $jvVDqF-SxN4iO>a^%TzU3Rxw=3t1A^fWd{ZbPV@ShQMu5g8C!VcUO0U~uLS.Rr4N{`4eWVk9qXX:YYjKF+YJ}#["},
		{true, Sha256Hash("fc96f2be60b43bc959f69c3470ef641d3880fc0ffa94c9c7862c50e78b83aabb"), "`n/3Le.a=$Qx\\LUv(4{+nsv`8i2|hp_~G82WUYkT)f$cN*AkLp9bm?3ja|h)gh|kG4eHxR\\r(h\"x_kt2_.T,z!'F@#!wy:c%<4(uli946wIk2\"&\"<f\\>bH H"},
		{true, Sha256Hash("3306c473b847f8cfe5414cfd07cd9c7c82108e73df0ee477326043fc2962d829"), "c BiT^da62YF7U0M3Zu1j%$F|DPEH)M3.NgzYe3z@nrbu<[? FB#2=4;|W;94cU@{u,TZ0HlX7 qnQ*e&o\":C43AnW2S5>Tf0KB=jM|nE52A-bJft\"Ee$Fe9v"},
		{true, Sha256Hash("40c9d807dc580f02b6b1707978faa224ca3327137ae2b404988441ae20e893a9"), "/i%!YTIj$nEku$Z1k|#S,d;C?1*h3}:AMQ%SBMH'hN-Ax&T.H;#vy]}s2ML`\".5&S%e$!9TYct;lNlQD+tpL=`:>DhyIWvy]\"Bp@C@H/p&z`mPC|V1vUSvE?)&"},
		{true, Sha256Hash("584eed5c85aecd9a15b51e27898e1385423482c24e04b45b67febc48bf27d6d1"), "^Etd8,p\"w2CZKcxB92ltY+.[7p1ZUH`YK\\e|1`BWYxSCuS m8.M&k!Z% !jRHxB+7Z-)]lb#m:W_8&fuP%/)o!E3|}+\\69WA?Rx=9S.R};J<*5Lt:vY7h}>c+Zh"},
		{true, Sha256Hash("abdcb903ad06ad2390fe022479f3dfaccf9681158fbb8252bbcbb93a8e649c63"), "kNTDAA@w3k.:D{)F:PUC_V0J| b]),JdYKD4A/?0*v\\08RV~HK(7TfTb1q9F\"C~n;\"7DQ~!N25`\"]U3\\B\\q(0p\"UwNk({jN. ;B\"S+/na(s>\\&u30[y7^aLM[)e#"},
		{true, Sha256Hash("fcb82031934f1d3b3adce0616c729b75231dc26703630f994c68f1b5a71e1b4c"), "FwVM,sn\"#w>\\y[9krCH%^W/.>\"W3p%7+{lgIMvZpsz,K4#|9Rs[>p\"|o{7CmX'SRTnCr:I.uR#<Vq:dKI$4\"d+GfXt=:yL*Wz~tR6lMCw)JOoHl}nLkjyoJB48X{G"},
		{true, Sha256Hash("e214c459dfc66ab4e36d4ba625f9a95805147749743da27f515a04ea616a0c18"), ">6xVDIi]tN*Y'pp6`3i7Hb\\.Z>\"D6O&uV$vG=_gdEfXwYeAiD%g$F=.qw9@)V4d*R\"[5#m.r'\"^s-CL~H'o:,!5}|.)yUjH/yBlK^LV}v?47FdY,RG:#`Su-<~sKci"},
		{true, Sha256Hash("107c1212954cd5ac0435cabde0e9d1135ec07d8c42802a00b571f2c8292775b8"), "T3#F!B+w`l($](cORXRw5f'/N1S.5sLfbfNhcuSRi0*5E5b$?M%_QGcI/+=Xlwo1~WewY|Y7q.j<rE95-\\?-EteTnO!hh4V\"ucruMc\\N6-@CDDDZ  Rv'`M1KGX(69G"},
		{true, Sha256Hash("2f04a53a7a557ab8d986ba961eeb417c33d1c411399092affa33ed0f13f5c504"), "[SX]k-w:t,bsdb$(hvN9CJcCR]ln<tpVi0#]-1D\"2SF~t/Y2ITCYWVm|3DvVpK-q{@KrP*+32ZqcMx=`(=##(#53W%[(Y)on.@<g0JO,ic(A_nCF<@ItmGO)S^45ZWBT"},
	};
	for (unsigned int i = 0; i < sizeof(singleCases) / sizeof(singleCases[0]); i++) {
		TestCase &tc = singleCases[i];
		Sha256Hash actualHash = Sha256::getHash(reinterpret_cast<const uint8_t*>(tc.message), strlen(tc.message));
		if ((actualHash == tc.expectedHash) != tc.matches) {
			printf("Test failed\n");
			return 1;
		}
	}
	
	// Double SHA-256 hash
	TestCase doubleCases[] = {
		{true, Sha256Hash("56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d"), ""},
		{true, Sha256Hash("58636c3ec08c12d55aedda056d602d5bcca72d8df6a69b519b72d32dc2428b4f"), "abc"},
		{true, Sha256Hash("af63952f8155cbb708b3b24997440992c95ebd5814fb843aac4d95687fe1ff0c"), "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
		{false, Sha256Hash("55b852781b9995a44c939b64e441ae2724b96f99c8f4fb9a141cfc9842c4b0e3"), ""},
		{false, Sha256Hash("ad1500f261ff10b49c7a1796a36103b02322ae5dde404141eacf018fbf1678ba"), "abc"},
	};
	for (unsigned int i = 0; i < sizeof(doubleCases) / sizeof(doubleCases[0]); i++) {
		TestCase &tc = doubleCases[i];
		Sha256Hash actualHash = Sha256::getDoubleHash(reinterpret_cast<const uint8_t*>(tc.message), strlen(tc.message));
		if ((actualHash == tc.expectedHash) != tc.matches) {
			printf("Test failed\n");
			return 1;
		}
	}
	
	// HMAC-SHA-256 message authentication code
	HmacCase hmacCases[] = {
		{true, Sha256Hash("f7cf322e6c37e926a73d83c900c21d882bf10bafceafa85c5338dbd8614c34b0"), "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", "Hi There"},
		{true, Sha256Hash("4338ec64b958ec9d8339279d083f005ac77595082624046a4e7560bf46c1dc5b"), "Jefe", "what do ya want for nothing?"},
		{true, Sha256Hash("fe65d5ce145563d922c1f83e8b095929a78191d0ebb84d85460e80361ea93e77"), "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"},
		{true, Sha256Hash("5b662967f43f2e7a07f878e5a3faf0853a08f2999881cca40e3c449a388a5582"), "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"},
		{true, Sha256Hash("c520cdb0aa60f8938bef8a6a0a7c6ffa2b5555296c790c6ee00e10737416b6a3"), "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", "Test With Truncation"},
		{true, Sha256Hash("547fe30e0f04460514c5283721c60b8e7fb7f5cbaa268a0d7fb6e01e5931e460"), "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", "Test Using Larger Than Block-Size Key - Hash Key First"},
		{true, Sha256Hash("e2353a5c53517f8a9313074f6463dcbf44e9b0d5bc5f6327cb2f941ba7ff099b"), "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."},
		{false, Sha256Hash("f7cf322e6c37e926a73d83c900c21d882bf10bafceafa85c5338dbd8614c34b0"), "\x0b\x0b\x0b\x0b\x0b\x4b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", "Hi There"},
		{false, Sha256Hash("f7cf322e6c37e926a73d83c900c21d982bf10bafceafa85c5338dbd8614c34b0"), "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", "Hi There"},
		{false, Sha256Hash("f7cf322e6c37e926a73d83c900c21d882bf10bafceafa85c5338dbd8614c34b0"), "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", "HI There"},
	};
	for (unsigned int i = 0; i < sizeof(hmacCases) / sizeof(hmacCases[0]); i++) {
		HmacCase &tc = hmacCases[i];
		Sha256Hash actualHash = Sha256::getHmac(reinterpret_cast<const uint8_t*>(tc.key), strlen(tc.key), reinterpret_cast<const uint8_t*>(tc.message), strlen(tc.message));
		if ((actualHash == tc.expectedHash) != tc.matches) {
			printf("Test failed\n");
			return 1;
		}
	}
	
	// Epilog
	printf("Test passed\n");
	return 0;
}
