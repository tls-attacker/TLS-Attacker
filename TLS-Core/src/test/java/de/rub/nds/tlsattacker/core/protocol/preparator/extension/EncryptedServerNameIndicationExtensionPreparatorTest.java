/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptedServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;

@SuppressWarnings("SpellCheckingInspection")
public class EncryptedServerNameIndicationExtensionPreparatorTest {

    private Chooser chooser;
    private TlsContext context;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        Config config = Config.createConfig();
        context = new TlsContext(config);
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, context, config);
    }

    @Test
    public void test() {
        CipherSuite cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
        NamedGroup namedGroup = NamedGroup.ECDH_X25519;

        byte nameTypeConfig = (byte) 0x00;
        String hostnameConfig = "baz.example.com";

        BigInteger privateKey = new BigInteger(ArrayConverter.hexStringToByteArray(
            "04DF647234F375CB38137C6775B04A40950C932E180620717F802B21FE868479987D990383D908E19B683F412ECDF397E1"));

        byte[] recordBytes = ArrayConverter.hexStringToByteArray(
            "ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412000213010104000000005dcc3a45000000005dda12050000");

        byte[] serverPublicKey =
            ArrayConverter.hexStringToByteArray("fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412");

        byte[] clientRandom =
            ArrayConverter.hexStringToByteArray("00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100");

        NamedGroup clientHelloKeyShareGroup = NamedGroup.ECDH_X25519;
        byte[] clientHelloKeyShareExchange =
            ArrayConverter.hexStringToByteArray("2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c");

        EncryptedServerNameIndicationExtensionMessage msg = new EncryptedServerNameIndicationExtensionMessage();
        EncryptedServerNameIndicationExtensionSerializer serializer =
            new EncryptedServerNameIndicationExtensionSerializer(msg);
        EncryptedServerNameIndicationExtensionPreparator preparator =
            new EncryptedServerNameIndicationExtensionPreparator(chooser, msg, serializer);

        ServerNamePair pair = new ServerNamePair(nameTypeConfig, hostnameConfig.getBytes(StandardCharsets.UTF_8));
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

        byte[] resultClientEsniInnerBytes = msg.getClientEsniInnerBytes().getValue();
        byte[] expectedClientEsniInnerBytes = ArrayConverter.hexStringToByteArray(
            "A7284C9A52F15C13644B947261774657001200000F62617A2E6578616D706C652E636F6D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

        byte[] expectedClientPublicKey =
            ArrayConverter.hexStringToByteArray("85372B06CBDA79BF6DE0152093851AA646BC25B4209DD3663F1E948F24C0E66A");
        byte[] resultClientPublicKey = msg.getKeyShareEntry().getPublicKey().getValue();

        byte[] resultContents = msg.getEncryptedSniComputation().getEsniContents().getValue();
        byte[] expectedContents = ArrayConverter.hexStringToByteArray(
            "0020B045EC64136934560D15F6FDE789FA515C666EA0B2979BEBDA671B298B6C2B9C001D002085372B06CBDA79BF6DE0152093851AA646BC25B4209DD3663F1E948F24C0E66A00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100");

        byte[] resultRecordDigest = msg.getRecordDigest().getValue();
        byte[] expectedRecordDigest =
            ArrayConverter.hexStringToByteArray("b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c");

        int resultRecordDigestLength = msg.getRecordDigestLength().getValue();
        int expectedRecordDigestLength = 256 / 8;

        byte[] resultContentsHash = msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        byte[] expectedContentsHash =
            ArrayConverter.hexStringToByteArray("9D72DC675D37D3336E5C5D4C3B1F528C8B01D913AFB1105BE56CD1F293030574");

        byte[] resultSharedSecret = msg.getEncryptedSniComputation().getEsniSharedSecret().getValue();
        byte[] expectedSharedSecret =
            ArrayConverter.hexStringToByteArray("D96C9A005C0897F5988FAAF671750AB4CEE1F60F2E965E9BDEEEE79F8B2AB06B");

        byte[] resultMasterSecret = msg.getEncryptedSniComputation().getEsniMasterSecret().getValue();
        byte[] expectedMasterSecret =
            ArrayConverter.hexStringToByteArray("AFEA7067E50CC72025C0AF44900AE00C3ED32277D8888EEA2C2FAAF724C942D4");

        byte[] resultKey = msg.getEncryptedSniComputation().getEsniKey().getValue();
        byte[] expectedKey = ArrayConverter.hexStringToByteArray("82FC17E07BB336C770F423A78EB506A9");

        byte[] resultIv = msg.getEncryptedSniComputation().getEsniIv().getValue();
        byte[] expectedIv = ArrayConverter.hexStringToByteArray("EADB1A925CF4517998C312A7");

        byte[] resultClientHelloKeyShare = msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue();
        byte[] expectedClientHelloKeyShare = ArrayConverter
            .hexStringToByteArray("0024001D00202A981DB6CDD02A06C1763102C9E741365AC4E6F72B3176A6BD6A3523D3EC0F4C");

        byte[] resultEncryptedSni = msg.getEncryptedSni().getValue();
        byte[] expectedEncryptedSni = ArrayConverter.hexStringToByteArray(
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
}