/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.hints.QuicPacketLayerHint;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.packet.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeUdpTransportHandler;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class QuicPacketLayerTest extends AbstractLayerTest {

    private QuicContext quicContext;

    private final byte[] sourceConnectionId =
            DataConverter.hexStringToByteArray("1d541e5371a5e1c6c481b6d7b07f0961");
    private final byte[] destinationConnectionId =
            DataConverter.hexStringToByteArray("8bf5abc395aa5e36e8c0b304a1352aa5");

    private final byte[] initialPacketWithClientHello =
            DataConverter.hexStringToByteArray(
                    "c600000001108bf5abc395aa5e36e8c0b304a1352aa5101d541e5371a5e1c6c481b6d7b07f0961004486053bb376267be1fc5bf74b2641fadd0002032b60b82c1b79f0c53e99bf1ec6bd3ebfb3d34e1c6903d8e625b973c50dd2bebd5de93209c61b1d182fdc31523345ae0ffd508f575b06c10d5b46fe4f1720bbce7217d0ad0dc8b10a263ebc424e5faf4494554e94e5a54e3e438e04762125e8fa1869c7ff0b640b0f73f8147734d8ccbdfcf8e19ee33a1bc12245f4f599ed47ec0e7843bdc2affcc817c8719a9674ca97321fb7a4129b47a24276e7e34ec9c2bc73206f5fc263ad4be77a7c84cf1694c2fc151b3122e2b0b5953694ab3c13c7c1d780dd257ed54dfbc30754c98418070e3becb0be1dfb37f8713ad345e8b9bba7e27b28567c49f37849b68775ad87eca2ddddab2477d98260321535a187ee7a539411d1620eeaa9f966a7deb5159d583b4dfb4e4ba3d0f30184bbb1088bd176c03f069d20b4758ad1f3a0a619db3516152ab505954fe6cb420468e8629103ef38aec3c0072ef703f973ccab6da6981a0f43b526cd766feb08e566eefe29a58b05ad5b0268ebdd54056f11f9fe1320827db04662b81803a87aabcde55edbd2e19fa755bbec1538c50c994100ff4a30748d4a03ea0a21f34bd6bad926b9b9b535b288150f0e28b1f198543bcdad87949ad2c06a650f7f7ec7e9fa27cca753cf4243030dc7b02270dfe5c0068fb72adee848fdedd4fcc8cd55e89af07bc05bb648d870cbdf3ae798af8356871e235529846d91e0f730caca785982193842d2a7576249ad4bf2b29b508c58585e03f4a8e9698ea4d55ee29c74f2271fb6b46dc8e7576821a1edc6905836d27a866b3d423bd332590009acab45ea739d8b10f83c4e9167994a8a0ae075705275aaac3a70e4911c3a4ffd9442f84a1c5c88d8ea3536f3ac1990008a3ee72b38e5af429e67bc63c53fe705cd691d8cd87d11c2ca6fb2b69db1a37e87c3475140d21ff1fb0c5144e341be7df1aeda148844e03ca75cbcbeeb3d706cbe643195172b5cdaad93b5ce46765ad4d4ba27e39d3401cd9f46da5113ac0a5e911838f86d20f6fbae7af175b31fc10fe9e16507bfb68baeff702bbdb211bd47086844f9d88603815c1e6cdea3110ee3ecb6f6ca09f94a00458d9f33b94f70bbbe23e214c0a50685587b7ded8be644710cc63c3ed3e2a2a251db6a4b982aed7e2c71daa9661a7b2c30be873def4f6c501f0bbe1ca9fd13fcf7a62fb25327c6412164b744ddde4df9d2f0f9fc5ad810d8488c685bf082348a2717f4c38e46e84e80a03be476d0cb1bcff71974a7d13a6bb71845c920d6d793c788d2046523714b559615f9a4906331db10bda12fbac4acf40f73cb8ccae3e050df2882ed6569970ab0bf23d8b43bb0b65f589c7d84d9b373d0e3f49c36a2c10801a3517077dfa4591882d24808919188dacdbd0630b70c2d72829938e1d41e47961eeceb2d5f97d0e5d8fdad1b4ba8b2bc0fce17726836dd546bb65b02e97664b31e748d13120eecb1b89c9e3c747de816b7d337bbfe2306cc8b90ab43df14fed4b6d88d42262f000dc24ad135d1d463e93103928b2d0ffc1c53f848ed86ebd10ea737f1b9d07febf0840577d83b808d29ebcb537f281a6aee1b3f2815f09c970a32726ed7a37eef1cce8816edba90f86b7a155351a051");
    private final byte[] clientHelloInStreamFrame =
            DataConverter.hexStringToByteArray(
                    "060041720100016e030360b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c0325f41d00000e1301130213031304130500c600c701000137000a0004000200170000000e000c0000093132372e302e302e31000d002a002802020302040205020602010102010301040105010601020303030403050306030804080508060708002b00030203040033004700450017004104f249104d0e6f8f29e6016277780cda84dc84b83bc3d899dfb736ca0831fbe8cfb57e12fcdb031f59cab81b1c6b1e1c07e4512e52ce832f1a0cedefff8b4340e9002d00030200010010002d002b0268330568332d32370568332d32380568332d32390568712d3239046563686f0a68712d696e7465726f700039006101048000ea6003048000fff70408c0000000802625a00508c0000000802625a00608c0000000802625a00708c0000000802625a00808c0000000800400000908c0000000800400000a01000b0247d00f101d541e5371a5e1c6c481b6d7b07f0961");

    // Two client Initial packets both using the client's randomly chosen DCID (8b19ddf6481a3718).
    // Both contain a Crypto frame and Padding frame. The second packet is a retransmission.
    private final byte[] initialPacketWithClientRandomDcidPn1 =
            DataConverter.hexStringToByteArray(
                    "c600000001088b19ddf6481a37180825e411b65c38d660004496c1740c1a68386db5a038ca0678e31b8ea49a5695faed391a9fefb31e10c0b4e3f28e76aad61e4ff553c50122b8ccecdc4d56ba548f09151e1535948602c715724b37df5164000f086516bd06aa967c2f5c5dccd90dff423b957034f64ede5bd58cea7119224a72d1521e1a255ec4ef02f2cf99e559cc690d6bcde0487dbefe9544607b17171e61d912a43838d65bb574dcc1dd97fd29b6e2b716d99f72d6e884c6e9bc213b731023d13c0b3ddaab67a1ba2e623ec612bd0275ff5095fc849736452554f2dbffe108d4d1e12b1b661aaf5102dd0c49c5b0589bbe40479e5a42ddeff72214a6bccd44db0b924f3a1f7112e4884e8dfde2fba937f206fd49eb8a671218ceb8c2a5e30ab566474291dabd0b275a4bd59b4a5ce9436ae8895a4cc2b25f006527880888a0e7a7e66158085aa5e7561e68987ad07f662c8e467dabb1b0971dc852ebf648e6b1eed57db24d8f236025c0fa90180634541dc70d489496b41506c9e2554392397d962bd969106cfbe5cca2c96dade60d91ebe609717b3c7c2ba01d7df8100e356d1efc21939d95b972c72ca3c016bb1857b8470558d5de8b6f4cf7176e584993c2dccec849a6c3f1ed755f5d9b990ee05e0b00e429b3bfcd8e18a23390b05f727919cbcd8224cf3e4cee9ce2b16c48c0d1cf9951c00dac23856af910cc3e31f4cac81bcaa34bf64b53b9a3024c149ed095a24d4ab3eadec0e19700417117ad526543ca77e5350b2a549ea810722f0ae21e13c049b4dd6a5ea5f7923c922c75a5daa4eb7e104e5fc7ce01e724ffa6cc418a521c574da77bbc09d855ae6aab25afc27a8994f6c29f896a8a3d5cc14256982f57ef2a1104b6e2f64a9470626bc3d47a4ad3e363a8c91933b3f8757297dbeca991764b5a1c9af12cabb1dc523ff838a849b7eb51ea44480f84a7aac82772119e3c4b6838471aaf462e8384c402896cc8c66cbe2f68d99302562eb58d26e5e71c9ac859205e341f9b481d619b26a40e8a3b4c990db34d5cf8d50cdfa5017e561bcc83c141ca95d0e60c9d3ca46393dab624e258dff064a93ec6c618c52006b3c2daaec69c6fa22917295584cd6533b68e917ec18313b2a51a0208366dcfee2ae1479eeaeeb766d83f5db8df50308da18cc31865d75ba80b1d4adc4c419534628c8e1a7bb70b1c69638520627bbf130441e41eb7274f4bb4c8648dcc841c0cda9e57d149ecefffacf061a877675e6b3cc65f8b841b46276cc18b2f5fd300dce635e0344c980e359de94de2bd2361620a406f9626d48cc0ea20f6e7ca6a606fb0f33f1d33d05038a5c27992701956990ad5348df6386d75f5b6cf1759ac51850ccd197d6a8e8bb6db3e86c8148345b69d14e47e07c11feed975e49dcc1117c356992d5a020a8774f2af764ad0a36d3086778a58e89d0cdbdb35fa55c58d63e7a1b724db34ddc9b1f071344e965da68d9bbd9754bbdf91ead035a3a8d5c71015d003e3006f6e7ca5aa2442d40e37b4a2e76db203a76379d0f2e8ff93a301ba2e2a721c09e7a4332c238d378a055cab218d2f7b6807c32ca07a9f146ca7b71c044cbe5bb73d9d50110ec2f1ea192492538e1ceff266e4111b138eee27b3de1a3f12ae05ce127e88251b202060fabd9cc4a558619cd48f6c458d05c8ab6c20da");
    private final byte[] initialPacketWithClientRandomDcidPn2 =
            DataConverter.hexStringToByteArray(
                    "cd00000001088b19ddf6481a37180825e411b65c38d66000449689b2fa3b625b14f4fe9383b1822c0ef307d89abaed03e3b24d0855a371838f1f7f9a003482387996a1cd95a2afb03249ae2f9c3220bf404b6edc84b26106b547e7055e96ccd13f8ef89a10895735818965b8399d2907afae8a0d8b0e93d9e890c8dcc80b8f88c1aa64678a181b77834f60f9943cfc9c53cc714e2dfe12133ee5b3ae598b56cb51899c87f1592f354896b845a09f41813214a8450a8c9aa563c44989d1cb1d0fdb37244aaf59351d62e21d288b24987ef74f1c2eb2e5a41a0bdb67f52c7bc3cb5a0ec117954643cfb5737c871d452c5fa72025a12f5578e657c08acdc88c9077b84fa29565f4417aa930731abb629736e42803b94d987f1f7b07d15509d4630b4a0dcd7f8c4a5679000f9a6f343115ca3f3eb052a76bcf4e11fb43986e7a5d48f9f1e52be131012f809c0693de0864e4d8ce2d07f400fac2831ef608333cdb71854c02c5ea9a604309d19488273b41de8173362fed62462f84bb801068ab1cf655344037aa942b3d8b4505d3e8b56db039c2325d7a98abff83fe6dec252bc5c9d29ede94aaf02435be1dd63aa315a6028e0da768bfbeac572a5af462364fc0a6bcf97e879c7ee54084fbac4e59a7e43b17db78e5313a2ceb9765e33d5d1d5697db7cd9f7db11aac002f97ee54dd75f70b704a341adcf23c5cb2319d715c5c7cd66532ab27d930233ccce15637d23f279a550134671c19c1b90ecb53844a9f2cb3d5fe65654a9c9dd033406f593c0a946114def324175d52436de3f283ece6cc67e5af6096c888b7e969f78e2bd3fc5d27610a7c65ba8cf9a7dfee0dcaa56523ed064ced6baf457ccc9b4b6610a4a5b9d94a580fb7e783fbbb36a347462262ad2bf63538db5640e6d76bf9cd68483e1c2812321157736dc17b7d3f7f10bcd987e69defb9249f17cddb74a91e0592f3b29b3cb4fad5e5e60ad66dbadafbd5159c060eaa7ad5e6124943c19076d61144c10b39dfe928c33b4218a68be6bafd9b422f025bacc12662db2ff2d31027ad769dffe68daec2c496f28ca2200cbc988aab7b490e09d605f44d8bba1cf1cbcbae4817569cc341d02b4e9e914f303f3c5dbc61f76b627a5204d3fbd4d14ff0e33d1ad2886d6f4bdd25b1718336ae3af26bf507800db9c6fb9140fb249bc14d4924ac775bd81a5129bb30b9d03a19b8a0b3c820ec5631df022fb6cabd6c9f342038e0ffc889d05c5e88014cc391d74a241042b6108666a9f2ef1b2c8dd3b65f32c40e4d9a244b3c0da871cc66c3cb39862bff69ad621d14a954d65048be7952e6595b741cd102e14e6b328d5ab3ffb6810b35c1f4edd811898a90f8507487b1d5b70d9d751fcabd5364f3505ad3068410a5cccda6af6cd97806b4eca5c656ee69259eb1875a5be4182fcdb3a179c38f5650f3d03cfd67a1c95ddee5e3efb2931ecdbd277ffb6b9f807836b543bf838b59fa24bbb5ca2011892cffc52ecdbb67f5203f877e3caf8baaca95d6eb6df13fb3cdc7207462abda21ac8813791cfc3f2e3f14732c359c3db97d43e18356f02785284d53c13b477949a846766558d5c41d66e0027f87898c842188c419c24b01969d43c4c8624a72625dd2949fb7d01cb536f0f0ec40b81f9b3419483069b442f0efff0af711b73ff3133d3a64027e445319d4f");

    // Three Initial packets for the connection ID filter test.
    // DCID: 3550eeb339d281b3 (client's random), SCID: 744ce95e375def3e
    // Packet 1 uses the client's randomly chosen DCID. Contains Crypto + Padding frames.
    private final byte[] filterTestInitialClientDcid =
            DataConverter.hexStringToByteArray(
                    "c700000001083550eeb339d281b308744ce95e375def3e0044960314e2449fd5e0d36a2d542e5dd75d370f294679b69c2989b796a3e23e5b96f59bc638a73f2044775a879b3f17cc81348f9113511bd11e2ea6ebc5496c63756281dfade34311611234c6c55d77c8b3dd3ac50d30027a395cace9e54080834c951758c34978a45d2836ea09f2d12d02f93d8a7a0fbbffc9f0c653a257b5e906a976709fb3bbc409ad5c7266d2311ec689c478ad4f1d964d3d9b1c1a647a50006a62d190cd3728bcddf3321d9137a12248ba41dadc8527b05ceb6ba7428e8c5866e0c307e47b7fd7f833ee2a1950d1b914de500e4527b231049d7ef3476097134f114d1ba7b072e67f9018c07e0385307126cfed27ac23fa817535a9a4fc3c58ef19409a0f2e218b1066dc89120780fac413c04ada2fce827a8eff524e11aa7f19e2f815efc6cc7ceb8e12f93c4be8cbd59cecf3465452c1df4b5f5f98b241bed8d4a31ec29b389d757a15756cf4fb7c64ce2a1cb05ec717ef7036b1361784d749aba427c8f0ebbbc304fa10fe7c71da20f4913cf1a2916d6bfe3154f016b0564bf893849c41013072e4185bd83dbc57ff3a73be8b2299edc7b8aeefe0f2084e28531338e03f313e321efb3ac927523475ef87aae820caf1fe38f53e29d864e65ed8c4fa8fbd91a90ade31cae929be6ff8d5229bc5f66dc756e63f95d4f6f00eedbf1fc090c07930854dd0b69b479e16b661caeffa73547cfa24bc7cd1c57a2357b4b62e2cd6f2b061ce5a05af78b46b183ccdc7eb3be6b0f0ea6d36a491af954ce910f241c548dea8268d0f803ac80087eba9f6842b78d5f3506d499830c3e6839ae2de792763a9958bec538efda5b94f316fb59f08fc11baa6424aecd46e6307d3672d00b17d1f6d5a2aa5a1cb8f33e4a9085388435d1a785cbd38621a712029c9d8ef0727817fc03110323597b1ef89e98b622dcd8d96a7f8590c46ce0184440be54848998224c23f6a360122a1e58376a90910f9c55f4f44fe4f21bf3b00a31114be36dec8cd387c115d7f64aa48482d8baf0f72683a55007092fcaa3a5580e4d1c820b80aa1b142081bc9888ff63bb83cc73ab4d7121ff41a8e6ed1dba5f7b764c2778e61165a6ea10498e461a58b2b1b07d583ab095ad21c27cfe1ce4f9d52da00fb371db4ff4f8021133e20c9e29bb321a683b0e58ba1cbdab89a4ff324f4a3578a42b6f57d730f15431c335be818b07e242d5eda81f04a2b197b7f95fce927470f4dc949ebce1f6976ae2764aec64de0a1d9280236badad35f5d36a67ea4991a9c753e6aaa98cb4e917e886a6a3709adf6d702be8523d559d9ce0ba5b77dfb58e2f9eef00def775158e61413b71a758a2760d5715191e6350f2ed33a0b8c5fcbfdc45825e77ac10eec8324d0260b4f4b68f1aa319f733b8d75ec9147d6db75027d1f0dd184fd9337ae607f7a43a1822c19a8899576391328d9f18d6ed4ed1de59b44d591fbf043adafe969e0dfa83077faca424b4ba11dc71cb72f226215b3e7eba657db1f48148b28c8a32c53632c515fa2253d9032f1b588e4194f98b345494d8fd32afc8ae381933a7d619e8b4937aa87db71dee9156393cc59ab53b4310368f48587d45086f71fd9c00e64b1b5ef9a2efc54d25ca0fae6f4084530d2d8e77fbcc8c69525f32cf7f77bba72000a2ef79a64");
    // Packet 2 uses the server's negotiated sourceConnectionId as DCID (60b420bb...).
    // DCID: 60b420bb3851d9d47acb933dbe70399b, SCID: 744ce95e375def3e
    // Contains Crypto + Padding frames.
    private final byte[] filterTestInitialServerDcid =
            DataConverter.hexStringToByteArray(
                    "ca000000011060b420bb3851d9d47acb933dbe70399b08744ce95e375def3e00448ea0e02b137ac359b58727c5a8c1b3411d0e47675d28f99d203d98b59f638ea77871a00dfb68a4f740d65e91bcbcb7691e946b24ba4b1d2721d9526615a504e885b3be75aaa04de1ecc232e9f345d90ffecd86b7c721c8b9659e08d43ca82cdd392f6cd6fac15e39ff438380b0f22029778ca597e0b8ff1ace1e54e9a52d7b5b422d618e804e4d5ac5ab7dc83bd64526eb7220b1b469384bbfb2262ea2cb2d09764baec930ec878e5ea8966e3efb6132a9799f08c8c7acf46dd3009299f9903025a77ed2ce531870c4585c768081c1e19a18d03df34aeae0735fa05fc4e6e42461062f9dd016ec5e62437c8b283d7468c63b613b5492acba79909990c9227aa16af9408d78d091f61ce42c765f5746ba846f212f9a907bb80c3138986f5ddeca0fbf8579a72f7867e34974c097a18f1f4fa2d37c499e3840a551444da8fff6b07b136f05cb4dbf6c74a7598b206f25c412421f4bccf9568bc6fbc00000194c903baa365aeecc1afdbba2dfc0b0d52d5352f592ec048f585ca4030f61c9304a3007622b0e5f12c63ebd6309d1f86c0bd5447d86c36b779b804dac0a956cb663ea2ce07f6840c70cae1bd620a2445aefcd07795ba568a63b699765b30c9a792d422e8c6e6722b50efd44702a4bf33bef52a6a124e91312a3987f1309de7d711b5baff2e5c81d11541ba24e4bf4e7d46009919a7e557d32374545022cbbddd3ac24562f6c0250131134b1814cd6fb4e0ebd205c87c9acbc7b2f74150429d04ff7c5e227571daf7f20a10bf73d7b433248404e680314a1f8045cf39cad1c2e65c9190d7614d6812a1d3c47e534b99fe41a542214946d9dd8ecf1c3662bb66b22f27470d16631ccb730d5345fd1bc8ac36f654d1148a9255ecee39c7940a7c182ad28b25680035403085c463c458fc315195cd5387e4b307e373687c83fdce9b81781f1b849bf453abc93f9f9079ff3571e19ea8071716f921bb175942fa267c6842b51528909b8a2bf6e271f3a1213da7d61fe3d5305d37d2f7ff4aa163584aed406d1f8c8839bd3006c9c190593b9e794e1f51c7a269ade0ae0c2c4541274282493042fff3b446f4b3aa5fa74f1aef8f4a269a14fff6294badf1cc60c7dc151512485d04f1af50c39e8d299cf621b13cb11c5e5ac0cfadce09eb087cb6b81533a5059dcb7d85cf23ac22675aa4e6dcf1056609bf238062d36d05626c8c24cb8bff2d8e9b8499d9576eb017cc8df012c5068eac5bb60dccee5446edc94fc171c4726866fb178576873d22a89d10dd8ea82fb65dd1f671c6f5146dc9b3535a41e73f4792b97bd567536ba2c93b227264af075b432cd8d518a7a2245eef3cfacc739159bf8193e9f57c324f90e08929184e9096bf35bf6e45504d5db2f96d9c0691ef3b3dfc197c58dab5757bd48f0649da33530ba35178d0b8722d275663db97aa8b29eb0bf1d357d532ba6fd886bf431ac3750e6f6b10d6033aa402dc3092bbffd1447633bb01a7c1ccbd57326c9e4341237f7db791dde34384cec91af59e2f81ca7384d2fe9708c3bf8206cfbadbe8d57ed61afaaf2d3847b16f56b72173d60f0b5bff709ffcdc533ee260387b3f85443d65594d07676adae08e8a793070ff26941e435448a5a2d552fee84bcef57128a");
    // Packet 3 also uses DCID 60b420bb... but will be used to test rejection when
    // sourceConnectionId
    // is changed to a mismatching value between receiving packets 2 and 3.
    // DCID: 60b420bb3851d9d47acb933dbe70399b, SCID: 744ce95e375def3e
    // Contains Crypto + Padding frames.
    private final byte[] filterTestInitialServerDcidRetransmit =
            DataConverter.hexStringToByteArray(
                    "c0000000011060b420bb3851d9d47acb933dbe70399b08744ce95e375def3e00448e83cf77d0688af114c1dc2ee7580a7db1dadebfa5cd28898a1ae9b24c995d689ddb7ee92320aeb32985dbff8941595b65221f38824c8e12c09aad64ab05def341ba8d6fd5a3fc722f1e1e429023aa046ae07520c2feb8234f9bab1b6260dac4e494efc50877d66a17f266a0972b846457e5ee74f00b36d1c30a4ba90bc66c2d74e2320323bd25a499656add9fc104824f9958c71c125850fca616893aac371eb1fbc4ad8d5d821a7bbcf5d2f94f9f638131d7ac7d7972f4a46c2f847bae30618c0acabf2b92f95951e347989fd6f96e76bba34207bac85627cb3bcf015be46203491cbb815f3d24f58bc76e048981f84ed8a6f66ddcc29f73c7b6a2a0ea61cacaddf6e86aa67b327f13b0fd5357dc1f661aac0298664f209735c7f928315e6d21b34c19c08630128946e93d05e3a14016b7bf870fbb0d47bebc6f18cc7ed3e486e776495cd01f801501600de6536d6d18cb02a83673430882b117d6190195d19551d21192bf3c652f545e6f46fe1b32dd755ac1832507bff479faedf71a8bc739dc541e52a4ec15852778150c3faf40ad12ea34989d60b2b286362dcede7046eca5fb0a229077ad20631a17644b22749d2d72247047e4e969f4167a614a30c8d0f5fa8a8ef8fcda3de90e6d749d81cd42d50e801ff908061a037b70e91aca8d2e4193078fc2fed918061e653667c7a8a7b8afebe4def712be4ded6292e40d8423795db84bd191690b845038f26f78240ce17e32d9756201bc2d4f1468b3576caf2d093901fb3954fda1ba0bd1445b25f26b23efade3203db20237526d84f38cfecbecae1aa2f6134914993a1b850fa29abf4608e2fffd1b9f360fb6ad471b59599ba26915df7ef0a5e7bfe7c10fe83cd9648698159071e873bce409c925acd24ad5345fa07603c1cece0175e113d421368ea16191a08f53631f8ead73e00b8bec3e477b95d0366bc08d174ac0be63d3bc1df7b723540048697ea24b4c9932fa9d14d2554f91597d5e9c1e311f7cda7e7cf48e935e7eaae9d9c276c1e0e46ae751beb2af06b80b7e6eed5ce770400f796b6923140fe3ae15a1697ead1cb331e1c35b50ac0fae57f1571b4a6fefbfa4a16249f2ef923d61bb5ebbc1705e3b8e340087b56dc91f50c88c1f3aa2369311b42a2cc3ed2d83f14d840aeafc2831031630ef60ed2140c0b2b75cf2da9fc15d5329d649e7f939c6725c6aee20b35ddc8f4e34949f34a9b2a4904d9ba0281a118bb2434c3abce438bb36e388ce5db63570e6d103e7453e5963b045833c7ad860370cfd8851db0dcbe8aa4d939f3bbcc9ebafe58485c5067c9f7d261671b4a73c75d6d1238090b8f1bcdf046bdc347aed111a6f0ccd9051c9d34214a3bd04edbb9af067b5e3785f14403eff4750e59fad706b671f6a4cdd4ada4b8f84500b28658053cdcc035308db964e662b03d449fff28c907ea483bcac360f0a14b9e07906509f868b494e4685caa16dd929c59a1b8034bb435589af804ee51aff1cd837a0ce80547c67837085b2fbb6c36ee25f1e043cfefc5737e5afb87645742cac867dbf87479c9f895f72bcd556db09ff79bd6716647697482d9ab1367ab3ffa1760035cd695f7c93bdd9c9f4ce1ca1ed19c4311c7c1929bb83256b68e994602b35ca");

    private final byte[] retryPacket =
            DataConverter.hexStringToByteArray(
                    "f000000001108bf5abc395aa5e36e8c0b304a1352aa5101d541e5371a5e1c6c481b6d7b07f09611234567890abcedf1234567890abcedf38e430eacef649a6bee5dcd72feeaf12");
    private final byte[] versionNegotiationPacket =
            DataConverter.hexStringToByteArray(
                    "8000000000108bf5abc395aa5e36e8c0b304a1352aa5101d541e5371a5e1c6c481b6d7b07f096100000001");
    private final byte[] statelessResetPacket =
            DataConverter.hexStringToByteArray(
                    "c600000001108bf5abc395aa5e36e8c0b304a1352aa5101d541e5371a5e1c6c481b6d7b07f0961004486053bb376267be1fc5bf74b2641fadd0002032b60b82c1b79f0c53e99bf1ec6bd3ebfb3d34e1c6903d8e625b973c50dd2bebd5de93209c61b1d182fdc31523345ae0ffd508f575b06c10d5b46fe4f1720bbce7217d0ad0dc8b10a263ebc424e5faf4494554e94e5a54e3e438e04762125e8fa1869c7ff0b640b0f73f8147734d8ccbdfcf8e19ee33a1bc12245f4f599ed47ec0e7843bdc2affcc817c8719a9674ca97321fb7a4129b47a24276e7e34ec9c2bc73206f5fc263ad4be77a7c84cf1694c2fc151b3122e2b0b5953694ab3c13c7c1d780dd257ed54dfbc30754c98418070e3becb0be1dfb37f8713ad345e8b9bba7e27b28567c49f37849b68775ad87eca2ddddab2477d98260321535a187ee7a539411d1620eeaa9f966a7deb5159d583b4dfb4e4ba3d0f30184bbb1088bd176c03f069d20b4758ad1f3a0a619db3516152ab505954fe6cb420468e8629103ef38aec3c0072ef703f973ccab6da6981a0f43b526cd766feb08e566eefe29a58b05ad5b0268ebdd54056f11f9fe1320827db04662b81803a87aabcde55edbd2e19fa755bbec1538c50c994100ff4a30748d4a03ea0a21f34bd6bad926b9b9b535b288150f0e28b1f198543bcdad87949ad2c06a650f7f7ec7e9fa27cca753cf4243030dc7b02270dfe5c0068fb72adee848fdedd4fcc8cd55e89af07bc05bb648d870cbdf3ae798af8356871e235529846d91e0f730caca785982193842d2a7576249ad4bf2b29b508c58585e03f4a8e9698ea4d55ee29c74f2271fb6b46dc8e7576821a1edc6905836d27a866b3d423bd332590009acab45ea739d8b10f83c4e9167994a8a0ae075705275aaac3a70e4911c3a4ffd9442f84a1c5c88d8ea3536f3ac1990008a3ee72b38e5af429e67bc63c53fe705cd691d8cd87d11c2ca6fb2b69db1a37e87c3475140d21ff1fb0c5144e341be7df1aeda148844e03ca75cbcbeeb3d706cbe643195172b5cdaad93b5ce46765ad4d4ba27e39d3401cd9f46da5113ac0a5e911838f86d20f6fbae7af175b31fc10fe9e16507bfb68baeff702bbdb211bd47086844f9d88603815c1e6cdea3110ee3ecb6f6ca09f94a00458d9f33b94f70bbbe23e214c0a50685587b7ded8be644710cc63c3ed3e2a2a251db6a4b982aed7e2c71daa9661a7b2c30be873def4f6c501f0bbe1ca9fd13fcf7a62fb25327c6412164b744ddde4df9d2f0f9fc5ad810d8488c685bf082348a2717f4c38e46e84e80a03be476d0cb1bcff71974a7d13a6bb71845c920d6d793c788d2046523714b559615f9a4906331db10bda12fbac4acf40f73cb8ccae3e050df2882ed6569970ab0bf23d8b43bb0b65f589c7d84d9b373d0e3f49c36a2c10801a3517077dfa4591882d24808919188dacdbd0630b70c2d72829938e1d41e47961eeceb2d5f97d0e5d8fdad1b4ba8b2bc0fce17726836dd546bb65b02e97664b31e748d13120eecb1b89c9e3c747de816b7d337bbfe2306cc8b90ab43df14fed4b6d88d42262f000dc24ad135d1d463e93103928b2d0ffc1c53f848ed86ebd10ea737f1b9d07febf0840577d83b808d29ebcb537f281a6aee1b3f2815f09c970a32726ed7a37eef1cce8816edba90f86b7a155351a051");

    public void applyDelegate() {
        QuicDelegate delegate = new QuicDelegate(true);
        delegate.applyDelegate(config);
    }

    public void setUpInitialSecrets() {
        quicContext.setSourceConnectionId(sourceConnectionId);
        quicContext.setFirstDestinationConnectionId(destinationConnectionId);
        quicContext.setDestinationConnectionId(destinationConnectionId);
        try {
            QuicPacketCryptoComputations.calculateInitialSecrets(quicContext);
        } catch (NoSuchAlgorithmException | CryptoException e) {
            throw new RuntimeException(e);
        }
    }

    public void setUpLayerSpecific() {
        FakeUdpTransportHandler udpTransportHandler = new FakeUdpTransportHandler(null);
        tlsContext.setTransportHandler(udpTransportHandler);
        transportHandler = udpTransportHandler;
        quicContext = context.getQuicContext();
    }

    /**
     * Re-initializes the test state with SERVER running mode. This creates a new State with an
     * InboundConnection so that QuicContext has ConnectionEndType.SERVER, where
     * firstDestinationConnectionId starts as null and initial secrets are not pre-calculated.
     */
    private void prepareServerSideTest() {
        config.setDefaultRunningMode(RunningModeType.SERVER);
        state = new State(config);
        context = state.getContext();
        tlsContext = context.getTlsContext();
        quicContext = context.getQuicContext();
        FakeUdpTransportHandler udpTransportHandler = new FakeUdpTransportHandler(null);
        tlsContext.setTransportHandler(udpTransportHandler);
        transportHandler = udpTransportHandler;
    }

    private ArrayList<QuicPacketType> getQuicPacketTypes() {
        ArrayList<QuicPacketType> packets = new ArrayList<>();
        packets.add(QuicPacketType.INITIAL_PACKET);
        packets.add(QuicPacketType.RETRY_PACKET);
        packets.add(QuicPacketType.VERSION_NEGOTIATION);
        return packets;
    }

    private ArrayList<byte[]> getQuicPacketsBytes() {
        ArrayList<byte[]> packets = new ArrayList<>();
        packets.add(initialPacketWithClientHello);
        packets.add(retryPacket);
        packets.add(versionNegotiationPacket);
        return packets;
    }

    private ArrayList<QuicPacket> getQuicPackets() {
        ArrayList<QuicPacket> packets = new ArrayList<>();
        packets.add(new InitialPacket(clientHelloInStreamFrame));
        packets.add(new RetryPacket());
        packets.add(new VersionNegotiationPacket());
        return packets;
    }

    private ArrayList<byte[]> getQuicPacketsPayload() {
        ArrayList<byte[]> payloads = new ArrayList<>();
        payloads.add(clientHelloInStreamFrame);
        payloads.add(null);
        payloads.add(null);
        return payloads;
    }

    @Test
    public void testSendConfiguration() throws IOException {
        setUpInitialSecrets();
        ArrayList<QuicPacket> quicPackets = getQuicPackets();
        ArrayList<byte[]> quicPacketsBytes = getQuicPacketsBytes();
        QuicPacketLayer quicPacketLayer =
                (QuicPacketLayer) tlsContext.getLayerStack().getLayer(QuicPacketLayer.class);
        for (int i = 0; i < quicPackets.size(); i++) {
            quicPacketLayer.setLayerConfiguration(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.QUICPACKET, quicPackets.subList(i, i + 1)));
            quicPacketLayer.sendConfiguration();

            List<QuicPacket> usedContainers = quicPacketLayer.getLayerResult().getUsedContainers();
            assertEquals(1, usedContainers.size());
            assertEquals(quicPackets.get(i), usedContainers.get(0));
            assertEquals(
                    Arrays.toString(quicPacketsBytes.get(i)),
                    Arrays.toString(transportHandler.getSentBytes()));
            quicPacketLayer.clear();
            transportHandler.resetOutputStream();
        }
    }

    @Test
    public void testSendData() throws IOException {
        setUpInitialSecrets();
        ArrayList<byte[]> quicPackets = getQuicPacketsPayload();
        ArrayList<byte[]> quicPacketsBytes = getQuicPacketsBytes();
        ArrayList<QuicPacketType> quicPacketTypes = getQuicPacketTypes();

        QuicPacketLayer quicPacketLayer =
                (QuicPacketLayer) tlsContext.getLayerStack().getLayer(QuicPacketLayer.class);
        for (int i = 0; i < quicPackets.size(); i++) {
            quicPacketLayer.setLayerConfiguration(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.QUICPACKET, new ArrayList<>()));
            quicPacketLayer.sendData(
                    new QuicPacketLayerHint(quicPacketTypes.get(i)), quicPackets.get(i));

            assertEquals(
                    Arrays.toString(quicPacketsBytes.get(i)),
                    Arrays.toString(transportHandler.getSentBytes()));
            transportHandler.resetOutputStream();
        }
    }

    @Test
    public void testReceiveData() throws IOException {
        setUpInitialSecrets();
        ArrayList<byte[]> quicPacketsBytes = getQuicPacketsBytes();
        ArrayList<byte[]> quicPacketsPayload = getQuicPacketsPayload();
        ArrayList<QuicPacket> quicPackets = getQuicPackets();
        // The hardcoded test packet has SCID and DCID flipped as it was generated
        // as an outgoing packet. When SCID matching is enabled (default behavior),
        // this test would fail. Ideally, the packet should be regenerated with
        // correct CID values for an incoming packet, but this requires complex
        // QUIC encryption setup. For now, we disable SCID matching for this test.
        // See issue #1504
        tlsContext.getConfig().setDiscardQuicPacketsWithMismatchedSCID(false);
        QuicPacketLayer quicPacketLayer =
                (QuicPacketLayer) tlsContext.getLayerStack().getLayer(QuicPacketLayer.class);
        for (int i = 0; i < quicPacketsBytes.size(); i++) {
            transportHandler.setFetchableByte(quicPacketsBytes.get(i));
            quicPacketLayer.receiveData();
            List<QuicPacket> usedContainers = quicPacketLayer.getLayerResult().getUsedContainers();
            assertEquals(quicPackets.get(i).getClass(), usedContainers.get(i).getClass());

            if (quicPacketsPayload.get(i) != null) {
                byte[] payloadBeginning =
                        Arrays.copyOf(
                                usedContainers.get(i).getUnprotectedPayload().getValue(),
                                quicPacketsPayload.get(i).length);
                assertArrayEquals(quicPacketsPayload.get(i), payloadBeginning);
            } else {
                assertEquals(null, usedContainers.get(i).getUnprotectedPayload());
            }
        }
    }

    @Test
    public void testReceiveMoreDataForHint() {
        setUpInitialSecrets();
        ArrayList<byte[]> quicPacketsBytes = getQuicPacketsBytes();
        ArrayList<byte[]> quicPacketsPayload = getQuicPacketsPayload();
        ArrayList<QuicPacket> quicPackets = getQuicPackets();
        // The hardcoded test packet has SCID and DCID flipped as it was generated
        // as an outgoing packet. When SCID matching is enabled (default behavior),
        // this test would fail. Ideally, the packet should be regenerated with
        // correct CID values for an incoming packet, but this requires complex
        // QUIC encryption setup. For now, we disable SCID matching for this test.
        // See issue #1504
        tlsContext.getConfig().setDiscardQuicPacketsWithMismatchedSCID(false);
        QuicPacketLayer quicPacketLayer =
                (QuicPacketLayer) tlsContext.getLayerStack().getLayer(QuicPacketLayer.class);
        for (int i = 0; i < quicPacketsBytes.size(); i++) {
            transportHandler.setFetchableByte(quicPacketsBytes.get(i));
            quicPacketLayer.receiveData();
            List<QuicPacket> usedContainers = quicPacketLayer.getLayerResult().getUsedContainers();
            assertEquals(quicPackets.get(i).getClass(), usedContainers.get(i).getClass());

            if (quicPacketsPayload.get(i) != null) {
                byte[] payloadBeginning =
                        Arrays.copyOf(
                                usedContainers.get(i).getUnprotectedPayload().getValue(),
                                quicPacketsPayload.get(i).length);
                assertArrayEquals(quicPacketsPayload.get(i), payloadBeginning);
            } else {
                assertEquals(null, usedContainers.get(i).getUnprotectedPayload());
            }
        }
    }

    /**
     * Tests that two Initial packets using the client's randomly chosen DCID are both accepted when
     * discardQuicPacketsWithMismatchedSCID is enabled. Both packets use the client's random DCID
     * (firstDestinationConnectionId) which does not match the server's sourceConnectionId. The
     * second packet is a retransmission. Both contain a Crypto frame and Padding frame. This
     * verifies the fix in isRejectMismatchedConnectionId that allows packets matching the
     * firstDestinationConnectionId even when they don't match the negotiated sourceConnectionId.
     */
    @Test
    public void testReceiveTwoInitialPacketsWithFirstDestinationConnectionIdAccepted()
            throws IOException {
        prepareServerSideTest();
        tlsContext.getConfig().setDiscardQuicPacketsWithMismatchedSCID(true);

        QuicPacketLayer quicPacketLayer =
                (QuicPacketLayer) tlsContext.getLayerStack().getLayer(QuicPacketLayer.class);

        // Receive first Initial packet (PN=1) — firstDestinationConnectionId is null (server
        // mode), so the packet passes the filter unconditionally.
        // InitialPacketHandler.adjustContext
        // then sets firstDestinationConnectionId from the packet's DCID.
        transportHandler.setFetchableByte(initialPacketWithClientRandomDcidPn1);
        quicPacketLayer.receiveData();

        // Receive second Initial packet (PN=2, retransmission) — DCID still uses the client's
        // random choice which now matches firstDestinationConnectionId, so it passes the filter
        // even though it doesn't match the server's sourceConnectionId.
        transportHandler.setFetchableByte(initialPacketWithClientRandomDcidPn2);
        quicPacketLayer.receiveData();

        List<QuicPacket> usedContainers = quicPacketLayer.getLayerResult().getUsedContainers();
        assertEquals(2, usedContainers.size());
        assertTrue(usedContainers.get(0) instanceof InitialPacket);
        assertTrue(usedContainers.get(1) instanceof InitialPacket);
    }

    /**
     * Tests the connection ID filter across the full lifecycle: acceptance via
     * firstDestinationConnectionId, acceptance via sourceConnectionId, and rejection when DCID
     * matches neither.
     */
    @Test
    public void testConnectionIdFilter() throws IOException {
        prepareServerSideTest();
        tlsContext.getConfig().setDiscardQuicPacketsWithMismatchedSCID(true);

        byte[] serverSourceConnectionId =
                DataConverter.hexStringToByteArray("60b420bb3851d9d47acb933dbe70399b");

        QuicPacketLayer quicPacketLayer =
                (QuicPacketLayer) tlsContext.getLayerStack().getLayer(QuicPacketLayer.class);

        // Packet 1 using a client-chosen (random) destination connection ID
        transportHandler.setFetchableByte(filterTestInitialClientDcid);
        quicPacketLayer.receiveData();

        // Simulate the server having negotiated its sourceConnectionId
        quicContext.setSourceConnectionId(serverSourceConnectionId);

        // Packet 2 using the servers real connection ID
        transportHandler.setFetchableByte(filterTestInitialServerDcid);
        quicPacketLayer.receiveData();

        List<QuicPacket> usedContainers = quicPacketLayer.getLayerResult().getUsedContainers();
        assertEquals(2, usedContainers.size());
        assertTrue(usedContainers.get(0) instanceof InitialPacket);
        assertTrue(usedContainers.get(1) instanceof InitialPacket);

        // Change sourceConnectionId to a wrong value to simulate a mismatch
        quicContext.setSourceConnectionId(
                DataConverter.hexStringToByteArray("deadbeefdeadbeefdeadbeefdeadbeef"));

        // Packet 3 using server's source connection ID - should now be filtered
        transportHandler.setFetchableByte(filterTestInitialServerDcidRetransmit);
        quicPacketLayer.receiveData();

        usedContainers = quicPacketLayer.getLayerResult().getUsedContainers();
        assertEquals(2, usedContainers.size());
        byte[] clientRandomDcid = DataConverter.hexStringToByteArray("3550eeb339d281b3");
        QuicPacket retained0 = usedContainers.get(0);
        assertArrayEquals(clientRandomDcid, retained0.getDestinationConnectionId().getValue());
        assertEquals(0, retained0.getPlainPacketNumber());

        QuicPacket retained1 = usedContainers.get(1);
        assertArrayEquals(
                serverSourceConnectionId, retained1.getDestinationConnectionId().getValue());
        assertEquals(1, retained1.getPlainPacketNumber());
    }
}
