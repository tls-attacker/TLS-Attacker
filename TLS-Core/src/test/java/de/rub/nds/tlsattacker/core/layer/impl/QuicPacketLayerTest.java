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
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.hints.QuicPacketLayerHint;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
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
        // mode), so the packet passes the filter unconditionally. InitialPacketHandler.adjustContext
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
}
