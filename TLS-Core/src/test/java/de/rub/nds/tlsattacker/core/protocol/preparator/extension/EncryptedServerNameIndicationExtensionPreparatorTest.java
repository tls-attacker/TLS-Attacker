/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class EncryptedServerNameIndicationExtensionPreparatorTest {

    private TlsContext context;

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() {
        context = new Context(new State(new Config()), new OutboundConnection()).getTlsContext();
    }

    private EncryptedServerNameIndicationExtensionMessage prepareMessage() {
        CipherSuite cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
        NamedGroup namedGroup = NamedGroup.ECDH_X25519;

        byte nameTypeConfig = (byte) 0x00;
        String hostnameConfig = "baz.example.com";

        BigInteger privateKey =
                new BigInteger(
                        DataConverter.hexStringToByteArray(
                                "04DF647234F375CB38137C6775B04A40950C932E180620717F802B21FE868479987D990383D908E19B683F412ECDF397E1"));

        byte[] recordBytes =
                DataConverter.hexStringToByteArray(
                        "ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412000213010104000000005dcc3a45000000005dda12050000");

        byte[] serverPublicKey =
                DataConverter.hexStringToByteArray(
                        "fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412");

        byte[] clientRandom =
                DataConverter.hexStringToByteArray(
                        "00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100");

        NamedGroup clientHelloKeyShareGroup = NamedGroup.ECDH_X25519;
        byte[] clientHelloKeyShareExchange =
                DataConverter.hexStringToByteArray(
                        "2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c");

        EncryptedServerNameIndicationExtensionMessage msg =
                new EncryptedServerNameIndicationExtensionMessage();
        EncryptedServerNameIndicationExtensionPreparator preparator =
                new EncryptedServerNameIndicationExtensionPreparator(context.getChooser(), msg);

        ServerNamePair pair =
                new ServerNamePair(nameTypeConfig, hostnameConfig.getBytes(StandardCharsets.UTF_8));
        msg.getClientEsniInner().getServerNameList().add(pair);

        context.getConfig().getClientSupportedEsniCipherSuites().add(cipherSuite);
        context.getConfig().getClientSupportedEsniNamedGroups().add(namedGroup);
        msg.getKeyShareEntry().setPrivateKey(privateKey);

        context.setEsniRecordBytes(recordBytes);

        KeyShareStoreEntry clientHelloKeySharePair = new KeyShareStoreEntry();
        clientHelloKeySharePair.setGroup(clientHelloKeyShareGroup);
        clientHelloKeySharePair.setPublicKey(clientHelloKeyShareExchange);
        List<KeyShareStoreEntry> clientHelloKeyShareList = new LinkedList<>();
        clientHelloKeyShareList.add(clientHelloKeySharePair);
        context.setClientKeyShareStoreEntryList(clientHelloKeyShareList);

        List<KeyShareStoreEntry> serverKeyShareEntryList = new LinkedList<>();
        KeyShareStoreEntry entry = new KeyShareStoreEntry();
        entry.setGroup(NamedGroup.ECDH_X25519);
        entry.setPublicKey(serverPublicKey);
        serverKeyShareEntryList.add(entry);
        context.setEsniServerKeyShareEntries(serverKeyShareEntryList);

        msg.getEncryptedSniComputation().setClientHelloRandom(clientRandom);
        context.setClientRandom(clientRandom);

        preparator.prepare();
        return msg;
    }

    @Test
    public void testPrepareTls13() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);

        EncryptedServerNameIndicationExtensionMessage msg = prepareMessage();

        byte[] resultClientEsniInnerBytes = msg.getClientEsniInnerBytes().getValue();
        byte[] expectedClientEsniInnerBytes =
                DataConverter.hexStringToByteArray(
                        "A7284C9A52F15C13644B947261774657001200000F62617A2E6578616D706C652E636F6D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

        byte[] expectedClientPublicKey =
                DataConverter.hexStringToByteArray(
                        "85372B06CBDA79BF6DE0152093851AA646BC25B4209DD3663F1E948F24C0E66A");
        byte[] resultClientPublicKey = msg.getKeyShareEntry().getPublicKey().getValue();

        byte[] resultContents = msg.getEncryptedSniComputation().getEsniContents().getValue();
        byte[] expectedContents =
                DataConverter.hexStringToByteArray(
                        "0020B045EC64136934560D15F6FDE789FA515C666EA0B2979BEBDA671B298B6C2B9C001D002085372B06CBDA79BF6DE0152093851AA646BC25B4209DD3663F1E948F24C0E66A00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100");

        byte[] resultRecordDigest = msg.getRecordDigest().getValue();
        byte[] expectedRecordDigest =
                DataConverter.hexStringToByteArray(
                        "b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c");

        int resultRecordDigestLength = msg.getRecordDigestLength().getValue();
        int expectedRecordDigestLength = 256 / 8;

        byte[] resultContentsHash =
                msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        byte[] expectedContentsHash =
                DataConverter.hexStringToByteArray(
                        "9D72DC675D37D3336E5C5D4C3B1F528C8B01D913AFB1105BE56CD1F293030574");

        byte[] resultSharedSecret =
                msg.getEncryptedSniComputation().getEsniSharedSecret().getValue();
        byte[] expectedSharedSecret =
                DataConverter.hexStringToByteArray(
                        "D96C9A005C0897F5988FAAF671750AB4CEE1F60F2E965E9BDEEEE79F8B2AB06B");

        byte[] resultMasterSecret =
                msg.getEncryptedSniComputation().getEsniMasterSecret().getValue();
        byte[] expectedMasterSecret =
                DataConverter.hexStringToByteArray(
                        "AFEA7067E50CC72025C0AF44900AE00C3ED32277D8888EEA2C2FAAF724C942D4");

        byte[] resultKey = msg.getEncryptedSniComputation().getEsniKey().getValue();
        byte[] expectedKey = DataConverter.hexStringToByteArray("82FC17E07BB336C770F423A78EB506A9");

        byte[] resultIv = msg.getEncryptedSniComputation().getEsniIv().getValue();
        byte[] expectedIv = DataConverter.hexStringToByteArray("EADB1A925CF4517998C312A7");

        byte[] resultClientHelloKeyShare =
                msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue();
        byte[] expectedClientHelloKeyShare =
                DataConverter.hexStringToByteArray(
                        "0024001D00202A981DB6CDD02A06C1763102C9E741365AC4E6F72B3176A6BD6A3523D3EC0F4C");

        byte[] resultEncryptedSni = msg.getEncryptedSni().getValue();
        byte[] expectedEncryptedSni =
                DataConverter.hexStringToByteArray(
                        "E3C48A706133928DB0E5307156F8FEA15A6D5451954D077B364FA40875517400AAC0A033D03971E8C7ACA8E8BBCC3BC8AAB9A74F645BA086127E9008592E0794491DBA30AE868721817646B8C503E134AA28834B755DE4847D1705ED9518B41B9D423B225CAE8B37BE6952CF0AE2B97D3860F6EC994A84C3273A26B8F8E39114539656B785D051C5475D072C5CA1EC054BB395AFEA5EA24A87692B0759B4928638F7D2BC6532C57DCAF3D53BEE825FDAED4D8E3BFB6C0153DF0D042D9A2BA7E8C16381234E71EC012749BF36D9E887A30191192A794B53F43948C2C7D1A59E54748007247E4EDFF3508DBC61AF01DFDF3A487D81315C615D3C1E1E819506B0FEEC8357E688D4841DE975B633CD18AB5031AEA93465A3382BA0A1E83FDE646DD99A349353");

        assertArrayEquals(expectedClientEsniInnerBytes, resultClientEsniInnerBytes);
        assertArrayEquals(expectedClientPublicKey, resultClientPublicKey);
        assertArrayEquals(expectedRecordDigest, resultRecordDigest);
        assertArrayEquals(expectedRecordDigest, resultRecordDigest);
        assertEquals(expectedRecordDigestLength, resultRecordDigestLength);
        assertArrayEquals(expectedContents, resultContents);
        assertArrayEquals(expectedContentsHash, resultContentsHash);
        assertArrayEquals(expectedSharedSecret, resultSharedSecret);
        assertArrayEquals(expectedMasterSecret, resultMasterSecret);
        assertArrayEquals(expectedKey, resultKey);
        assertArrayEquals(expectedIv, resultIv);
        assertArrayEquals(expectedClientHelloKeyShare, resultClientHelloKeyShare);
        assertArrayEquals(expectedEncryptedSni, resultEncryptedSni);
    }

    @Test
    public void testPrepareDtls13() {
        context.setSelectedProtocolVersion(ProtocolVersion.DTLS13);

        EncryptedServerNameIndicationExtensionMessage msg = prepareMessage();

        byte[] resultClientEsniInnerBytes = msg.getClientEsniInnerBytes().getValue();
        byte[] expectedClientEsniInnerBytes =
                DataConverter.hexStringToByteArray(
                        "A7284C9A52F15C13644B947261774657001200000F62617A2E6578616D706C652E636F6D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

        byte[] expectedClientPublicKey =
                DataConverter.hexStringToByteArray(
                        "85372B06CBDA79BF6DE0152093851AA646BC25B4209DD3663F1E948F24C0E66A");
        byte[] resultClientPublicKey = msg.getKeyShareEntry().getPublicKey().getValue();

        byte[] resultContents = msg.getEncryptedSniComputation().getEsniContents().getValue();
        byte[] expectedContents =
                DataConverter.hexStringToByteArray(
                        "0020B045EC64136934560D15F6FDE789FA515C666EA0B2979BEBDA671B298B6C2B9C001D002085372B06CBDA79BF6DE0152093851AA646BC25B4209DD3663F1E948F24C0E66A00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100");

        byte[] resultRecordDigest = msg.getRecordDigest().getValue();
        byte[] expectedRecordDigest =
                DataConverter.hexStringToByteArray(
                        "B045EC64136934560D15F6FDE789FA515C666EA0B2979BEBDA671B298B6C2B9C");

        int resultRecordDigestLength = msg.getRecordDigestLength().getValue();
        int expectedRecordDigestLength = 256 / 8;

        byte[] resultContentsHash =
                msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        byte[] expectedContentsHash =
                DataConverter.hexStringToByteArray(
                        "9D72DC675D37D3336E5C5D4C3B1F528C8B01D913AFB1105BE56CD1F293030574");

        byte[] resultSharedSecret =
                msg.getEncryptedSniComputation().getEsniSharedSecret().getValue();
        byte[] expectedSharedSecret =
                DataConverter.hexStringToByteArray(
                        "D96C9A005C0897F5988FAAF671750AB4CEE1F60F2E965E9BDEEEE79F8B2AB06B");

        byte[] resultMasterSecret =
                msg.getEncryptedSniComputation().getEsniMasterSecret().getValue();
        byte[] expectedMasterSecret =
                DataConverter.hexStringToByteArray(
                        "AFEA7067E50CC72025C0AF44900AE00C3ED32277D8888EEA2C2FAAF724C942D4");

        byte[] resultKey = msg.getEncryptedSniComputation().getEsniKey().getValue();
        byte[] expectedKey = DataConverter.hexStringToByteArray("29C3C3FFD8DF1A21A8326B8235941134");

        byte[] resultIv = msg.getEncryptedSniComputation().getEsniIv().getValue();
        byte[] expectedIv = DataConverter.hexStringToByteArray("FFA10A7FB3B08FAC319D478A");

        byte[] resultClientHelloKeyShare =
                msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue();
        byte[] expectedClientHelloKeyShare =
                DataConverter.hexStringToByteArray(
                        "0024001D00202A981DB6CDD02A06C1763102C9E741365AC4E6F72B3176A6BD6A3523D3EC0F4C");

        byte[] resultEncryptedSni = msg.getEncryptedSni().getValue();
        byte[] expectedEncryptedSni =
                DataConverter.hexStringToByteArray(
                        "12361671865F3FC9FBC0343EFD090F5F9C887FB302C9124687FD11A5FAB868E11182AC6C8B7240A7D00022BDA975E4596B05367C03B7ECBC9D331CB79EF1B93071D1258C211385836918E773A2E1C2FEE2C33A58FE7A28475C7BAFD8FDFBA0B5F7B5EB1D51ADF3C694716450FCDACB881FFB21A0C9CABFC1270BF6B01152316412E484058F45A9CBE933C86F6BF34B12305C238A7A2284A074B84F6FAF4AF89AEE7FCB79376AB458F717C9E8736E320C19DA3EA33BF761A02953F543F20B97580D7EF0952D714F8C77CCF31812D3978328B176BEC462FA5F47B08CF938C46DF7C26207BDFBE1F17A44A24DBB2A3E49730F37AA7D38AC0D3BD3669337D8F42400B350B416D507159A56000536ABA3A6FBB400C032AB4AD86EB85B0CAC7B894FED45862482");

        assertArrayEquals(expectedClientEsniInnerBytes, resultClientEsniInnerBytes);
        assertArrayEquals(expectedClientPublicKey, resultClientPublicKey);
        assertArrayEquals(expectedRecordDigest, resultRecordDigest);
        assertArrayEquals(expectedRecordDigest, resultRecordDigest);
        assertEquals(expectedRecordDigestLength, resultRecordDigestLength);
        assertArrayEquals(expectedContents, resultContents);
        assertArrayEquals(expectedContentsHash, resultContentsHash);
        assertArrayEquals(expectedSharedSecret, resultSharedSecret);
        assertArrayEquals(expectedMasterSecret, resultMasterSecret);
        assertArrayEquals(expectedKey, resultKey);
        assertArrayEquals(expectedIv, resultIv);
        assertArrayEquals(expectedClientHelloKeyShare, resultClientHelloKeyShare);
        assertArrayEquals(expectedEncryptedSni, resultEncryptedSni);
    }
}
