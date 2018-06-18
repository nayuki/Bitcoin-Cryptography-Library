/* 
 * A runnable main program that tests the functionality of class Ripemd160.
 * 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include "TestHelper.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "Ripemd160.hpp"


int main() {
	struct TestCase {
		bool matches;
		const char *expectedHash;
		Bytes message;
	};
	const vector<TestCase> cases{
		// Standard test vectors
		{true, "9C1185A5C5E9FC54612808977EE8F548B2258D31", asciiBytes("")},
		{true, "0BDC9D2D256B3EE9DAAE347BE6F4DC835A467FFE", asciiBytes("a")},
		{true, "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC", asciiBytes("abc")},
		{true, "5D0689EF49D2FAE572B881B123A85FFA21595F36", asciiBytes("message digest")},
		{true, "F71C27109C692C1B56BBDCEB5B9D2865B3708DBC", asciiBytes("abcdefghijklmnopqrstuvwxyz")},
		{true, "12A053384A9C0C88E405A06C27DCF49ADA62EB2B", asciiBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")},
		{true, "B0E20B6E3116640286ED3A87A5713079B21F5189", asciiBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")},
		{true, "9B752E45573D4B39F4DBD3323CAB82BF63326BFB", asciiBytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890")},
		// Mismatches caused by slight perturbations
		{false, "9C1185A5C5E9FC54612808977EE8F548B2258D30", asciiBytes("")},
		{false, "9C1185A5C5E9FC54612508977EE8F548B2258D31", asciiBytes("")},
		{false, "9C1185A5C5E9FC54612808977EE8F548B2258D31", asciiBytes(" ")},
		{false, "0EB208F7E05D987A9B044A8E98C6B087F15A0BFC", asciiBytes("abc")},
		{false, "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC", asciiBytes("aac")},
		// Random printable-ASCII test vectors of increasing length
		{true, "A7AB75AE5E53DBA6EEA54B2F74A08BCB03991CAA", asciiBytes("7")},
		{true, "613C79611BFC3C408FB38CEC52DFF48DC60BF101", asciiBytes("Zw")},
		{true, "33BD259D8C4E0D09B521CFE56C56AA7862A0A72B", asciiBytes("W5!")},
		{true, "B8333A95DF12C223A9D452B28DA36BE22B6B2F78", asciiBytes(";qgm")},
		{true, "BC23639E82007878BB9C13EE846B5799559F6AD5", asciiBytes("h1iLC")},
		{true, "2DFCBAA52A838ACF55C2BDF7F181779DEB1575C1", asciiBytes("\\*N:4s")},
		{true, "CA33478006746A6D26751407662C66D23F9E6DF3", asciiBytes("%k+<_X'")},
		{true, "3F70E8B406292B3C7B7086B10B05F915F6670D67", asciiBytes("v lZuX|I")},
		{true, "7D1D7F468F1E60213C620B8FEC05E10A47291629", asciiBytes("@!xO n'@c")},
		{true, "69271211B54A66B1536EC6CB3452E21DC3A9BC7B", asciiBytes("0[]]i!\"B7=")},
		{true, "4F8384BE0A76CFF1AA2F5D7037230BB33D577CE4", asciiBytes("z\\\"&?Ka_K#A")},
		{true, "D62B194B2DB73B37795FA37000238F22D36619D4", asciiBytes("<E`#7a8A@M`\\")},
		{true, "E47D80F5B15B7A617F88854F1C0F862726B4AF43", asciiBytes("A^~Cp~nm[2%Se")},
		{true, "D8000C6440AC79D3D77D9AC904315B25AE89E849", asciiBytes("=?e}nJz`l~~p_?")},
		{true, "B427EFA7ABA30F0EC7CE1F2EFEE8860826F56374", asciiBytes("wQi-E7-?_KU{Mv~")},
		{true, "1918477DBC4219894326363148F83630F61D8FEC", asciiBytes("0XI!\"DTejM pp2Qz")},
		{true, "938107075F3993EA311DF87EF6B0B6602A100DCD", asciiBytes("YKcUZT<u\\8c16!Hxe")},
		{true, "DF08604B0C234B54F5DE66C725451016FDA38D5A", asciiBytes("xIjGg]-T{yj(hJ4/~e")},
		{true, "EDA0125DC6E5C043B50A7ABB0D9E4AA21DB346A5", asciiBytes("c }Z|f*f?gzuk-JOn}(")},
		{true, "FA46AFCA3D9B6350340F4CCFAE4CA628F34E7423", asciiBytes("s-D~\\^MJfUDgl3`SCc,+")},
		{true, "64C37EFB87F02DA3A4820226A45FB455B9DCE650", asciiBytes("DU<07i]chF<,XvyOs)z3M")},
		{true, "EBB7492BEE6959A9A200DBF2D09A3A8D59091433", asciiBytes("zd xorp0-mq~`:cPHxZiR~")},
		{true, "E69EB70C4EA908A3758CEEBBDAD83CECDF920DC9", asciiBytes("uh4#(C.C\\W^|Ax7'UYMXS]s")},
		{true, "577B6F9DF07B2563533BD71D482169748E5C3833", asciiBytes(":bK#'VFHu'PAO~`E@(H_;,]\\")},
		{true, "14F441C3A165166C92B7A7D2D16C9A8B69130DEA", asciiBytes("u{go_);Z~+Z 67Al]IwueOu99")},
		{true, "217FC775F1647E6207A5A94C7317482392B65F2D", asciiBytes("g5?5pzBt3#B0eE0!bj;*:S8%;X")},
		{true, "77F2CF04A41A772A1A50D877C2D6BD44F67187E7", asciiBytes("g`~cyU~18Vhszb!sEEBJm!x~Ze2")},
		{true, "002075253CFB1CD1E8B7BF34F34A7DC4349A996A", asciiBytes("q$:j-0+{K`9<lRy<NQm,/R:-{~PC")},
		{true, "505A840BEFD63AA080B2AA65989886A48F5E7BFE", asciiBytes("gpD0gy__X[FlvGzhGRCte^^V86As9")},
		{true, "95D1A3B693267934B8B3C3FEC9C736AAC8783B72", asciiBytes("-6[1`(qf*JZY(&]`.B.$*ri4jndH@D")},
		{true, "E98635FDFEB78EA7D9F3BE50C7BBA51D61801766", asciiBytes("V}`Oyt`17qz37&ke[Jf&C?/Qeiw-{$H")},
		{true, "C63229CD71AD47FA3CCE02DCC9EE12B6574CFB11", asciiBytes("D@~W`7c?{g_$jy>1BT|Lch3_RDFpE`'6")},
		{true, "574F4B41985642D5E01442FA48D844ECAF1AEA4C", asciiBytes("SkB!qU8-@Kiw](<5KM5=4?v[`?@Me'8j~")},
		{true, "7B295840A7A81C0AAE530ABA2A5986F18E2859BF", asciiBytes("%90u+j8\\u&qf 9&1FT'a?xZ{vxbI}Iqz$E")},
		{true, "B5AB29B0EF24A8792E49013BD7294F1781BB7D62", asciiBytes("tJPhq&-t\\a,pF->~:3_^1m+^Nn</K(c!T4 ")},
		{true, "DFDE378B886C6E22E4AF927B2676E9DE91C122C8", asciiBytes("jevce\"SJo0'bb->[BF`1oAAY?2y;h3G[G~]J")},
		{true, "21D8A074D899065500A07BF23B1D2311DFCE3861", asciiBytes("V}QN-2XPNfz\"Ngq_:#4y2TyqP@\"f4~H69z))7")},
		{true, "05EE401564118701DF4739A1591607F60AAEFEC4", asciiBytes(":u'rQ4OJ!!%iyy)QZOzUeDqL/vdei7Dr-qSP Q")},
		{true, "EA6C7E377778A4F93A9E910269486F5F6514C6AF", asciiBytes("7YJ;'nyG6D>;owuzqZ6wRVs_'*Z'J?3zm}FJ4 R")},
		{true, "CB4C6052E5E162820A2A79E2868809CA9D3155AF", asciiBytes("&CBo|c)KL%3)T;.ZGJK#aBMqv'~^>N}+WS{DBgMd")},
		{true, "0CC571AA85BB93431231885FF2C0C403AD52852F", asciiBytes("')GV(P^!>!9|VocKUc`bDi312*)lhx}P'\\R8.N/33")},
		{true, "1AC3E42EBBD41182B5F2CFC6F5D2187C640540EC", asciiBytes("4)o@5;.7.>_|vcdNNKX4/GlGECm&wRDr.PM_ U};@2")},
		{true, "719442ACF3BFF29C83763D7AA1B92D6E7E2B89B7", asciiBytes("gj9RlD,Oi2I+ 9bofX6;j6OK!}.fKg,+qq@8 >`*=w$")},
		{true, "6830D2DE3BF5DAF7D8FA077A44B6B0270756A070", asciiBytes("57%7\"rO4{*_^ag]UPFk]oCd EjXvh5m+BvuVXx\\pntTj")},
		{true, "60E3392509C161D2DAC79031BF9049812F5454ED", asciiBytes("zk?*GZT#%Ar&/\\QV>\"*v*MuD(B|QJB%G-r|K)[XQ;#~ez")},
		{true, "9EE7F727BBC4EFFFA014D3C88A1F8FC0B6119926", asciiBytes("?E3RL0w 0tL1By]+l7iUNHCXcqPH<}e/8z*^'3Rl(J68Kh")},
		{true, "EAC8769249CCAB28014B3FB28C4E2C55CF05C796", asciiBytes("G?bggj&q=T@zew(O| Eh<sB{Xv5*>d$,8f4%>O'N!3[}/^S")},
		{true, "1ACFE2DBBFEE82016856D2C8A138DD29D1511129", asciiBytes("jM{jn~31bFAqkYP,v?12`pysg0y4$t[vLt'agA/xQOd$o`}[")},
		{true, "93FDC5611DA5D06C3B6FAF4A7660D3F4A5BE323B", asciiBytes("~MiM8'3os3-U~fcItV&>ABL,BG8a +E>TcEFO~s8ii^Y7_M:U")},
		{true, "FB941E300A192303293CEA51555C227235D03D12", asciiBytes("Wc}]AI5y\\SlWMltvrS9D\\@gN+5zHfSGmHV0ZaE3{m6<K18#m\"S")},
		{true, "68FD83E90B65D322E58934F5BF4668AD1C261601", asciiBytes("iw*SPVt-[2C.Q~IF@a\"Z9gZa+D/Wb*|4//30k/HOOZ~~u*~w& t")},
		{true, "B1C54D0BA9B04B5DB79C783EA289D230B6F69944", asciiBytes("mR_E:@h!b;ezs[NjQ8(YH8c8pwV)_5i+[R,7718L.T{}3F/_<c?m")},
		{true, "50E71D4A41452C68447557E6B51F13A60C1B2D5D", asciiBytes("htPSE[\\b5d~8)[GJW7dGwee0D0;XCd{k`YWw}8 |@!g}v!byANVBj")},
		{true, "26685929E531DEB3061374A491D4C6894D1F85B1", asciiBytes("600XTmm(sDg.Q1~?1fgsNc\"u\\ps\"lIR&+ktU^a{\"t@W?!Chc]\\A~:a")},
		{true, "7C8BF50AB381347BDFB8EA0AE53873D42C9389D5", asciiBytes("3DgU\\g'IRLPS/fZV16tu<>-Xq:-$3GWV4.pnM|ZPUX44y8mD@\\EFJ/r")},
		{true, "05519CB9B76D2D66D9206ADBEFCB2D8F0C2A6060", asciiBytes("\\JMJyRHaWF-T8>1/z@U5w:FkBZuK}<[ SQbTMoUcPW<;#K?1`P7j ,}V")},
		{true, "622EDEC7D5CD80422E42C6C7966E26FA3698B73B", asciiBytes("Wrh^q02KEd,TY`o0(O[[#c6@0PE xz{v$=l\\G3(40hT?~)kW!ON+Q10=F")},
		{true, "20561A54ECDFAE8B41FB0E0EA8B9A9A87683D20D", asciiBytes(".f2CegT06$UIO&_7jU}$qw+Ns7--j-  \\3XE^)/+Hzz7kOQyPI:QXA%fir")},
		{true, "F91425513AF00C637CCEC3D82EF24DECF7BDE75F", asciiBytes("YAH`Odube^oqNi`=&_ewVv!x;uy95A4yLL4lV0HG9a\\l@guA9OQ;:CAaPr;")},
		{true, "D5D675209CBFF9A99CC59A89B5D13A86104D2432", asciiBytes("z]qo'xcTx>QE(JW{;+{o\"Y'_k>,l(jNR`l4{T,!I mC4CVj@l5H1Q\"WAw=?0")},
		{true, "F26897C74901AAC296E70ABABD905516C3565369", asciiBytes("k-|uN*@\\\\=dE=JZQ)MRQ\"{*wud[;.}{W<cvyw*qW vwM6X\"<9R!>/$05z E((")},
		{true, "2B819D03F3E8331B4C6B34902D3EF923AE7CF8BE", asciiBytes("S{<mA*L:oc/_Rb5^pTZ[Akt_t)MR0dDsN'mqKh?bTN8Z's~9xI4FH7F8v-JnH^")},
		{true, "5448A70488E0EBEC5839A0CBF8B1F1EEC7F5C621", asciiBytes(":c'HdxrHY{v)7Z]IxWh8\"EN)MP8IEvrxs`C(,L{\"y$J{kXF5,SO%=.X_5c[TDLm")},
		{true, "4B8969CE6A0F7A4CD5CB562E521F2614B9DB6F81", asciiBytes("BvkJT%!\",E$T0x5'z.>cPU#3Qxz;v[`'(\"zT.,k9lAR}PH~BO?Ub!ZG zC\\sk--Y")},
		{true, "326EEA31D541479B460DCE095F98EA31FF567079", asciiBytes("(ENsp\"46'6NZz#G<|g_0@}qSasqNeN^(emx#S@\\te!/u.tx5Hz%z}#k9k;@lLpo>_")},
		{true, "0121DF11D92280EF983597DDD1077A7DDC72DF3A", asciiBytes(")gQ 8G[N0D#me6/RXX\\C\"q^_~=.$bm(^L.|(JenW/!<a_{4e](6W-:+gMEJx|l+2EF")},
		{true, "62522B6CCDD9101789D14EB8D4677D43EC7A5038", asciiBytes("[Lg^ L#N4>)|c*\"$aG#`ae0]7UCdU/{|WtX=0y=s_7#[I(=24YID}naTNlfp@H=G7B3")},
		{true, "FFAB6DB7B92C663D1418D37F9DE2F16CB5D5327F", asciiBytes("[)b_wsb)>0)M<8$|$#p<.9^g[G MgI'c**#:\\zXQ3LS(_m`+cK][ 1)o.Sn+XiYx\"KBh")},
		{true, "0797A989BEAE5645E32E9286F4CF9E7904D33567", asciiBytes("Sr)+VvXSWyDy#z.+:bOW6^|pJR,_834m#g0BdEks2lzdnOA:\\mxR2<OR0lOBBcdKfWb`X")},
		{true, "13D5435262997BB0C98DB495CFDC003C1BDC262E", asciiBytes("kRA^BYA]n>{.y|Ed{Ph1z(q#&fAvk?i3xqQ3b*QM*:UgUe5mLZIf9RW[x3\\kLbo]^1G4\"J")},
		{true, "1F06B8572E433135816155606382D2694C1F3100", asciiBytes("U]uFU`Hc4bW%xn\"ZtWtlkp$^09d2akWa&:.yOR56tv#g~b~ V,<y?uz3?daz:1na>|A`D}k")},
		{true, "44B9FB65CBE9CB255C1B1485BAE1A6B9452206C4", asciiBytes("DYdJ%>8Zd+2XGK*h]44i5SnD3GzL{E\"WlYxm!1:2:rc|#P2p9v,T<MMaK/}WI-$(c^L7LYU)")},
		{true, "85D9CE882BAFD17D93F8E90416ACCC574D9C586F", asciiBytes("iHhe@Pb,LurC#>;,B`cnW/B;gGko'I#q[hgq(yXT5g>8>L0S|w09xMiU<AkHqSFh$tnZSfW5z")},
		{true, "AC0387BA113F885FC14BBEA9D1A80DC3FCD6F1AC", asciiBytes("y=QG!_MP~31vp[#'o}*,|A<_Z-;cmtR'ij`U@Lxj52wf9'T'@LQBW55fs\\S+}TYv_1 w2P[\\$\"")},
		{true, "104CFBE7F4F16E82C046EA7632997B27065E6286", asciiBytes("sIZG2ol/*4zyCl<r84Y6n:#%Q?phcN)&1>+hyXh{AXT=q(-<-kU6>e(?3v%+dDp$mY)LB%:.?Mi")},
		{true, "1F254E4779F7DD322EAA5E4B6AF6E1E712183961", asciiBytes("Nv5PQ:v(+Cp=6suaC_gMo8~p_Dld$)B.7+)OpSBC?}|[OqIRel2R+K8^cU>29q}|%spD1SW8V8EB")},
		{true, "F240D7891EF1FFCD8AC4308261D9E8ED568D0418", asciiBytes("T&qTGpE\\.Fcl~E: <\"V*'IIIdnC\"XKX<q\\2?BNl*L_5SyP!M{Cl0=}i7ovXdPAm*rAnA*LK0v;I`Y")},
		{true, "6BAE58ABF6C4A98F7BBD7B64AA6E44AE1F06471F", asciiBytes(".E`\"DU0tW=}~b(%O>m<J./>=Tplb&h9kT#.n=w`<ZxMG)a[RBX9<~i]Hh]b8&ca_Al#h!Z3rZSaO ;")},
		{true, "5233572531FB161BA057AC0B478898621628B2D9", asciiBytes("H\\yo!UFMoc2i|Y/-$F<:[::h%yfu%-ItZ~6JE 9J.,G`D&{CVLn~nJmTg<E=_iImxq8 BuniP5vi0g~")},
		{true, "51CEE53BE02FA8B82E6ACBF35FD0793D9DEA8459", asciiBytes("Sl0.\\iiAI<ymxS>]H*<MF:G\\0<AU|n6[4:Moax^%m'yY}O^*C(bVSoyw=.'PBZ\\0\"GGv\\&X[HpnboXgb")},
		{true, "98B8A1017BFB7ABFE31498C3654EB862AB99DED7", asciiBytes(".@q$w:dBUeP9Zd<Cc=U.=<MPEBtQ^oKNjViLY)LS$r^,B9:bNs.OD<[9lQ7D>&]Ow%?Kb!]s?\"/Ow7#-'")},
		{true, "D173FF9985E178CA1E67CAFE973390D20A46B2A4", asciiBytes("|s=*WdDy\";%aQ2&ws.H8[}#5L>s+M 8!nFa)(Irwat&`@ jx4{C#Tx3v=WkmmqGL\\,u&7lGL)\"<C_=\"yhm")},
		{true, "31C7382EE4DD0B59837BE40F1996DDB6E6AA4378", asciiBytes("+pZJ<mVtcIGa{Y~F0?)/1hK@%y!< kprFlV5c;6=r~?v&Z)x:%~w~\\GGiE+w'yp#FWpq])S54{E<MqQz{t!")},
		{true, "42442C77973A3824E35D408F3B7FB85D8068657B", asciiBytes("YIg`Ga(rYi+]5DzwG,LP;FSY8+=2GZNVU(va2(cSf.;6j})X-+;h,$ jGo[KFYHN5wcK2:Ek:=Jz*&(SY\\8&")},
		{true, "FB0311CB9C1934ABA99CB00A917CCAEB284E9F41", asciiBytes("}C\\>x#EWfD,de(IG9<StN8WRCh2G?,eE/_@ox(5eqft:vc5gOhqGPIymY(n[gWjJ`R;m]FIx@>n\">0tRC>yH@")},
		{true, "2B0800E95CA2E0493F6B98CF38D20D07427970EB", asciiBytes("zpn-cTEUts\"A3+/91o;?GHlOz4~ }?|XFd,Gq#>N L{`AJ3_Zk^BD2]WFt~-3~F>!Lw^`;(lmCgk0Kq}f@un2c")},
		{true, "1B57134934A9B16289D33C53B1DC9BA7CD2EA39B", asciiBytes("5M\\^lb5.! (93i,'iRg'',owg,]:x}662<kmS!&MMu~cE^(jH>>)A}.I+^|aI./9](e9jsH< d.y)N%o3X:TzwO")},
		{true, "EA4A01C2A2C0843F08323D2AD6C40D8C0CE76F69", asciiBytes("$^+F825k@7MxGimL-~.JB>>U\"X+Uv+T<}4|r'^~8uV]~|zoj@P8P`QKmJsukDwNW\"pH1$C6tGpM[X5\"x_IQ-`Y<#")},
		{true, "31003BF4122026A3ADB6DF953E69B796881F2614", asciiBytes("gyVV\"Zxq1CH8&sn>O}L%zjDVO}$(QP)]JC}&IOp?'EM{D|OY^d(r;E`%4]+;OPf\\*w/oj4\\adgKH8?*X^I4~\\kTT?")},
		{true, "DCCF05E342F614A497C59D134AD6B7965868BEFD", asciiBytes("FAm{MogSYSUV]{h# p>>h0`HQ\"o~X%x&&-U4\"8t[r5mankt;i{ivjLNO^ax^&>]ur_Xn?)I=CxztG*\\w^af@->6D9L")},
		{true, "6604F4E0C9F0AAC75ED8DDE8B1094A590CABF4FD", asciiBytes("y~nOogR/ExXD>\"H^($,l]>%VsnxdD5d}vqxKr_[y._(p0=w-nn=i['K!p]b.m|;w4?nTU1w@c/9%8,I{$W|rpFxO\\Ba")},
		{true, "E25151CE3871FE6BA4DD28A9485B48F41E78C548", asciiBytes("4bgy=e?k8(9SJczbaRwI'.IBXJAT5]WO0QbfTU!BXA,LdYSI1DrI6;n Vn1D_.?W=<gOHw ifMOlbHeq1S!LeIh0I_&w")},
		{true, "66970A9A2A5E292179D94FDE77A91D71BF0256F7", asciiBytes(":qL,oZ_.r:H*W-:<^r<\\3uG}({_I fjPS<iw'@SJ`.y974pL;G_{t=6*65>@aA fJ4{oH|x:y&j(xz\\?zqgKS0GxfW3(&")},
		{true, "A0481C4F6D2EDCD13D34FE337ADA08027E9CC658", asciiBytes("huN%[llDd Js\\uDrr%lT8Hd4mU,%LP4Yei&Diu`cX*4 W>c7R?C])3u2yt=IJ6I7\\>`\".2&s$<.^?lacn.n%BvT-G>OuAd")},
		{true, "7446E01F15DDCBCAC51C8047A9D71E203B110E94", asciiBytes("XDw*tm2e1DRBy^>7h\\w=t'(|'khoaVY]21&3*W(@mL47J1>;Af#*vM;9[/6ib00m91Q-)^a7JtJ$otxn`$>,@){&3iOSRTc")},
		{true, "BE00B043AF1922D68A4137113BE5FC2ED40A4C4C", asciiBytes("2 U~x\\YAT~p1}!5/]pB:xN!;uE~S^4ba~+k8K=kbyY);BIpp3PBp[&M)3-$bu&_V&@'kIW#n2)D.;<B:`m8UXu85IR8C%|yZ")},
		{true, "EC26326620D37FE9C10E0B4B38BB1AC9DDB50C70", asciiBytes("%k)9EEA4(u(kBi}PEQlP|^?$[W99v,OaW%Cpzt9Lh8mG=Y|5,.WA)xJ]JLqNl3$X*1p$7}-x+LB/G7|tZRF+8F=*2EdsuOQM\"")},
		{true, "E0283BD8155843919D00F8BC9C9FC5F8D52A5AB9", asciiBytes("8jQ|HNcC+h`9,S{+8)s#.p<U4JB4U;#GXDCGAO/gf3HEV#[B4%`XH9wB.d)u,&%OJP?fsP9y-QD196aDW>k`Tn@K6a9;a4UzF7")},
		{true, "E3230922A215DEF5FF6776D2CEEBE8777FA98893", asciiBytes("_BG\"!pt4+y_.e!Pj# ]!7dhdl\\'6\"GCv(YMM[wCo+A4~^1]J\"9,[!c*L/R]vJUe^RPMEo|/DTo!ha<y'gt'CXb\"uhTk==C?Sq'*")},
		{true, "37E67379533161E582BB9E2D5569ECE207F9D344", asciiBytes("/VkU0]f~\"<p{:dVsJfy,U(Fx:?;6>|>vk.D:svP{i3X,'m1`\\gs4Cdr-&sBJDLw]u.>iye3FAwZ5~uRqepA+QkFQ5mY'6f5lQjuI")},
		{true, "FB261FDD70C62A1266ACBCFC22EAF6304291FE44", asciiBytes("3H#5',n)^1 `vZMH?aZGpZ',|q p<,-^-_<IJ7#nVp8KGUmd&`Qr!akaT:AeDB\"J@}})U.94}l)D9W@\"73f#t{;RIY!h}P1 F['Zl")},
		{true, "DD4408E7508E06A2F0B2D91783C1A870968AFD78", asciiBytes("=g6`(B2[)Mu0Aym'pBg08XE>ddr#nFE{'B7aFSp.z21La|U-&-$^/QnD8V6<X5JrD2@QW<AcPUO\\INb{/A~\\p~akyQP>DEzgM5F}oU")},
		{true, "576C099E3AAA44D60942E365D0389F77B77A90D9", asciiBytes("_jDD;? h~Sv1XQ\"u;i;VJDuBbpD4+$m$i:jZvvC0Lvs@*R~A#M3, HXQZ'N#P%H$I0a:rKanzM'jA%V\"p5}/puhl8#vkd92c<Nw4AsK")},
		{true, "74B71D05476EBE82A67E4EC08957BB942B35D0D9", asciiBytes("zo&gwFM{R,58PKX<@+Dfvdg#X|\\Xc3ue/@U~u+t}d zBAmCI9'<g|s|I17:U!IME]:>B\"yV)ZsK[4+]yVBocPu)x/Fsi($$xmH?WndEM")},
		{true, "E3A4289E966FF217AF8113DA1F94C48BCEAD94F9", asciiBytes("vmuxALB*fzZ631L\\j\"\\A+mio0WC;N0(g0-AKFm`pkkoI[4{r4K]8o*+!x=FC5a=:c)8d!p4U#c(9Y?^3Wc$C5t f]9o!8-Iiwv!5@255d")},
		{true, "80D047D66EB61423F14A83E4AD3FAAC70E5CCBBA", asciiBytes("(O@\\:S3ILVw5@Gz9RurLwH6L|^<o\"&(:m+mlgosIuLusU.iK2`EX'S}r1iz0tt8<99)4V\"\"AZR3_fPB}8AGS<(zlp 2 lh5S<ak1n{zT^O")},
		{true, "99552AA76B987D05CFE453B80AF9F507A5912870", asciiBytes("@O2|MC=mbZ7\"WVd`|XRVj^&x_v^Y:./F`*,{OOMS-kM\\G8EG|pWRPkL-)cC$u=1\"~L\"EpBA4>H7#g3y$O{C}t^7zd8!lBpB1l}? cNa(J@Q")},
		{true, "AB0F2B8A39165A9208CB1D16C708DA6D9733FBA1", asciiBytes("J}xl!r])Jai^V'eZF@:YwM\\j%pl(8#'-Cz8<0LQ_D)Z=+6W$rX3Nr5KFUM'\"xH\"Lo/jYXI-i$zt11oP|Y2YY>]YmrbYg~C,vaNH9'Ze=4br5")},
		{true, "328AAABB04463474AC9B34D8F05F2DF78AFDEA21", asciiBytes("Sv%h#I=mYk@*B(mk^!t7eKKm:czdxAP~sY!T&zKUWO$3\\9)l@1PsxsOIbx*~n{E u[e]zX<3yi,z~7 9?qC,A.;9BED=D{/c;i}H>3vT wTd/")},
		{true, "B4B531830F9C975BEC7C0AEA7466A835B7856F4B", asciiBytes("1^QDqvgoTyc;C HpCG`6Q^pF]tKh$Gh?IJPW%Ne/}F+ollAY>Bn{#&~#gpg5j%3i|_yjJ</szrl_/s4ga{Ur>#MD0$a4msW1GY-_.I[3tF>7dy")},
		{true, "25988674C88BB0E59515E7743FC0C33A45B61954", asciiBytes("h`A'-)`QRFC'`/!oV|5IAn>4rFJ)ZqgB#5eBrW9/Z0pMu*/y,r9oAZ,buZr#x!;:bx)B//T1y:KX6yd\\)'<,%*g!^h=(b$E[4@GdZB;HCrx.FL7")},
		{true, "CB2915F742C0C276B936134D6D4CA64F599C73A3", asciiBytes("y[V$h7#<?q5r_B$<v|n@/FK>}s&=L i~hz\"#<Vj]{iQb5BJVS=$R}fix,{OH,_'[AoNi;> &K6T1xaP|RI;}Bzw]S2\\O=\"!}j\"R]hpce_BguTmc?")},
		{true, "0EF4DF8670DD4CD37D139195521A5C407465DC08", asciiBytes("<r0%^~83!Y:KXxGV!OkV.M;qS*eOxYG0a0S3L}ZywaN:u\"N}rhv/vuSSOgV&\\kde2^;MLou41{a&\"2lk6>/np5*]mvH-vx/?rp!ye@+))YwU>-(d-")},
		{true, "094C4A58FBF99308ADE10FB37A865F7BAB0C9F91", asciiBytes(">[Ncg|^l ~=-vWXlBPx0a2t:-rt}T4(I,wPKmtxT^Sv'!m8ploI2Q%zWjhY!8$a,9H_;sL@Y:p+JkaM[JaGS\\qi=@RX3cD|QRiY'/gd)k\"v?03Br}N")},
		{true, "648D64F8B6EDD81C64698C3CFB923695D1F42462", asciiBytes("z^P.|cj/Q}1IRRg(s,<GyT1W6)&Ev\"TPWd75CIW)DpmLw/ {^t-GCyn_(_sJc)@rDxOm.j3?)bDeyD_8}aXv5j>l ,wi7PL~_+w$St2eZJt6V+wlLO7")},
		{true, "F54375AD5E2F606DB14C0872F0D853CC5D82EB6B", asciiBytes("/%CV~!7b#Ri6hyW$QJl$2eLfj>/>+IKniA/~|[b.:N--e%u@F].p{%Tte|r[]xRBkG@RgZtiwkTvlqdAen2SGs)yRmhVwG@v.6OW>^m2,Kii74t<!R~L")},
		{true, "12404AC90FCEB65927841DA37C46E9BDA62F19F6", asciiBytes("~,H6^NP7c:fM/ho#5 9g<Cvdj}ed(,3?~tH4R*i\"Lkqz`=1Mjb<$5yOcL`!75Q!bG5xmf_.$j6AH$GpEh\"l3Pki%,$Z{/mQ+Euc1/c:DkO!v0bn<wnYvi")},
		{true, "F4B6809F95743A45FA8B1FA51CFBC8ED19D3ADD9", asciiBytes(" 4:*|g SioQu?Avofkd@tBI@XjFMUAI0x[EQ>DULGOk|]66jQW9&nBf(})d6C!Sk4`3XcTLLw #KC#5fX.xFo^!\"$7#1*q[8uONtj~P:\"h0z3! Rnb.%:y")},
		{true, "F0593487F96B4FD053DA55E0BD90477F9B6E687F", asciiBytes("B/\"(]`m][z 4X_lp6w@[n]k%'KWHJ<tq^[=0k&ueiof:{C1$SlZk^Wr:Dzeql3AxE*X+5U;l%1_g/`&&=v-H;a-TPfRiikbyf&_ FXIPSHype8,D!;*P(`m")},
		{true, "2F8B776F55E087B799D50706CC8BA57571E56EFF", asciiBytes("=|w{3S&2 `;QR[eSHfq\"VeqrGHK9-EXTd)/jj]E[,.%nsMTP:7hP]1p\\JJn/pc_\"`\\XE4NPz>FN3N6SC/|hfy80%y@#V5_DkI$W8Y$5+F`n7hX:8'RZt`4vp")},
		{true, "9AA75D9760034869BB63D27A4C3AA46C4B58F5D4", asciiBytes("Ur>r^R@+,.{Z<)Xxai#z=JAQ*uD{}7FGq`xPHMcwxR/~~zgIG*~PL3yjhT${lVLehl/=(8K>yv\"zC$9NVH&m!lW.)3ti-{g1uun[\"3]\\[Lbg UB ~UagPzlg/")},
		{true, "4A4BAD72C801F779DBE4485AD74518EAA68F9D6E", asciiBytes("[mV8_@w)TW>)9De6J2*F%GJ5GtS7QKn\"9)2-@xp*.Atc[R:HF%7x5QJweR+|{DdR=2nH_3H5bSK-t!}!MTPHy^z7c3\"pl-d,Sf.uq>\"!Yy*>ZttpID3jLu>d<~")},
		{true, "C99BBDD95BFFAB5C450EBA147D3D9AB43CE79FBC", asciiBytes("0I*9jlf%8`|Q80BsGR4*MjZPLGd~8@\")viKk5ZPOnf,m]>p!M@4V[s'N6m)oD)o,y\"f5_q^I7l/qkH5#lFEz~JR~kvjf,[\\eU~/(T@?v?M`J9O<gaF2VlXf\")5#")},
		{true, "E92D11C52A77CAADEBACE541D276A32D244C1A50", asciiBytes("-e<`VK2l#X4V0YViVZShf7LM@-D0`C>4Jl(l${-6*2%UVlqt(uduX`+o*N}$-H-r~,{b8sc<!&\\uf0zUzmk3{bRNg->f>[po/xSB@fuK8lv~nq6Q2xH },<^;!tx")},
		{true, "684366B693565F4D248FEAE474A890D060CA0FB0", asciiBytes("\\WyTPch-u9|z\\%:sK,~Td7co6O1:o)t}>.TSfi=(\\H[IEP[>zMQ)PBv'&^U,e?(Buj1;p_u'\"5l*THUbK-{+cN$TPll1{bMln4@Vfw{Xy*lS6+Fw :`D>#3\\uD,Hp")},
		{true, "709AA693BD121A6B4306D2B671EEC41BAD92EEDB", asciiBytes("}XWNb%ba6h\\qG?!-5x'R}S93I>mcj6+FTKy c4fE\\](.1uD;qHMV]!qV\\HyvF;Yr:KDFcc<is?4$?nFe#w6\\+4]gLCgDWNb0Z&fD\\Ve<\\wM{Sdd_vIQHBgY1W#5kvW")},
		{true, "231ACC308E6A4EA80E18088BF327FED0E46FE4F5", asciiBytes("=\\PVDEXdkTOQX+-nEer=*K_Ce4U\"UFxZP#\\Pjx9'9 Uk _>M36r1n{u|vM0+8aFAO|a<]^EIRF_ ^nr>6DFV3~jYm-|MZ|pGx!2kpBY@&Ols'*3Ccn}J\\>\\C.)as(1A")},
		{true, "1290BA8D7D327925426113B2D04512D75E4E207A", asciiBytes(";/a7M/e\\`*@'_xA7]U}o#.\"[HL0m<TTO5-\\ XNGl8?g~`@O]bTm!t:|MG>G}#64gnq=FVzB$MEZW=.D:uoZ\\3:E~Z6Y'j&9duKTW24nvA2'.\"c7.kRn;Al3>}>khmFU>")},
		// Binary test vectors
		{true, "9C1185A5C5E9FC54612808977EE8F548B2258D31", hexBytes("")},
		{true, "C81B94933420221A7AC004A90242D8B1D3E5070D", hexBytes("00")},
		{true, "F7D50D120D655BE4B88750873E00CAF147F28A1B", hexBytes("0000")},
		{true, "1C451CEA274137364FD8D3D1F8990BB03101EBCA", hexBytes("002400")},
		{true, "1E2F6138A0F061704408EB66E2FBA65C380EAE38", hexBytes("FF80C95E")},
		{true, "47C2915DE1B326F065F54CEA2D9FFD114A07E0C4", hexBytes("26F96E8E87")},
		{true, "5FCCE2FC51D1CDB11DF0EAE5B3600C4A122BEAA9", hexBytes("CA1C3D868BB0")},
		{true, "FD079B14722B89198677B13AF2366F9388D05D49", hexBytes("4051CA937FD277")},
		{true, "B895D2BEB801EC926668BE6D807038E15CFCA6E0", hexBytes("9F720999FCCF0EA1")},
		{true, "D3A1C9D700908A9C7CEDCC717CD9379186213B6E", hexBytes("D2398D341E81302E79")},
		{true, "23FFC977256CBA56FC22C8EDF2BD524B747B6B86", hexBytes("16B465594145C439D3FA")},
		{true, "36F668FE3C19A9BE4665374322F1D1666D5413E8", hexBytes("A79A11116C71401829E286")},
		{true, "7D198C7B432D0019F44A05687DCE0D5251ED2F71", hexBytes("741C189E1E703ADE8C7DD823")},
		{true, "6E48333CAE83734A7457D945B2F5928029B57DBD", hexBytes("0207354350B35C07722FA4AFB3")},
		{true, "A09EC352C3ADC74F5EED4EDB3DB764F44B8FE2CD", hexBytes("94E8D77965A1E0E686749AB459D8")},
		{true, "0CD998103F24A3E9F749E89C2D15F003CF19F17C", hexBytes("64AE32F6976AC0019744C48DFB0F4F")},
		{true, "B78A645A28E94664C08FF98C515315D91EB688C0", hexBytes("1B6280E15BA61D91B623490A49589D83")},
	};
	
	int numTestCases = 0;
	for (const TestCase &tc : cases) {
		Bytes expectHash = hexBytes(tc.expectedHash);
		assert(expectHash.size() == Ripemd160::HASH_LEN);
		std::uint8_t actualHash[Ripemd160::HASH_LEN];
		Ripemd160::getHash(tc.message.data(), tc.message.size(), actualHash);
		assert((std::memcmp(actualHash, expectHash.data(), Ripemd160::HASH_LEN) == 0) == tc.matches);
		numTestCases++;
	}
	std::printf("All %d test cases passed\n", numTestCases);
	return EXIT_SUCCESS;
}
