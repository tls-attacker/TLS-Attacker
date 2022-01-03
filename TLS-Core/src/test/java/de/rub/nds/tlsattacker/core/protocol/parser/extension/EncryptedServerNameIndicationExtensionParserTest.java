/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;

public class EncryptedServerNameIndicationExtensionParserTest {

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
        byte[] msgBytes = ArrayConverter.hexStringToByteArray(
            "ffce016e1301001d002041f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d54000020b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c0124a133e3280209e18ec46ee8d37062f4df1ddc9a4d60de59fb57c284989f23fdb02da0ae115e87b57be927499ef19cf88424cd0906b915010f51a0b39be192ba10bcd6d6b47a1967439670278a433337eebd5695106e1d1ed38337e7ad71fb8f756bb527c096751da3a52604fb0859ded699e3cd2cbc47fae73819d8eb2c8dcf1eccc8502ac6cdb237e2541b85140aa83d9234e10ab0108ba81586a729bf26f95b32a9f7a89aeaecedf77fd3cdef8c58144e2a4fb359bb8a37483fdc135179793a6510d291b42b737ed9aa76b490bd6745068391831e6f2cc4370c44f0957cf932f58e8174a46dd2184a7e4950239b546a6b699b19f4e53668c2be2d2311b5965bb82ed14f22368c125a0a71acee5f06579fe9fb798f6a36092093ce32c591603c5b6b16ee");

        byte[] serverPrivateKey =
            ArrayConverter.hexStringToByteArray("b0b658b2287a55d9c261bb3feb0c55954be29366eb353b54f986acaa62f81e5A");

        byte[] namedGroup = NamedGroup.ECDH_X25519.getValue();

        byte[] clientRandom =
            ArrayConverter.hexStringToByteArray("e6aef9c483abf499f6a1c3befa5f16f854482072a0d3d29476c51f5c3d4d5709");

        byte[] clientKeySharePublicKey1 =
            ArrayConverter.hexStringToByteArray("33f34944dd62f7d40388729b584e5eb108e29b34c739af29ec5113fb2b8d5714");

        byte[] clientKeySharePublicKey2 = ArrayConverter.hexStringToByteArray(
            "0401e31149fb03eee9a101c3660bb29db586d1a347414f0c28011a5fe4805a355d37edfec598888d76083580f0394e754a4666f9a66678c23ae2058ac2fa55a459");

        NamedGroup clientKeyShareGroup1 = NamedGroup.ECDH_X25519;
        NamedGroup clientKeyShareGroup2 = NamedGroup.SECP256R1;
        List<KeyShareStoreEntry> clientKeyShares = new LinkedList();
        clientKeyShares.add(new KeyShareStoreEntry(clientKeyShareGroup1, clientKeySharePublicKey1));
        clientKeyShares.add(new KeyShareStoreEntry(clientKeyShareGroup2, clientKeySharePublicKey2));

        context.setClientRandom(clientRandom);

        context.setClientKeyShareStoreEntryList(clientKeyShares);
        KeyShareEntry serverKeyShareEntry = new KeyShareEntry();
        serverKeyShareEntry.setGroup(namedGroup);
        serverKeyShareEntry.setPrivateKey(new BigInteger(serverPrivateKey));
        List<KeyShareEntry> serverKeyShareEntries = new LinkedList();
        serverKeyShareEntries.add(serverKeyShareEntry);
        context.getConfig().setEsniServerKeyPairs(serverKeyShareEntries);

        EncryptedServerNameIndicationExtensionParser parser =
            new EncryptedServerNameIndicationExtensionParser(0, msgBytes, context.getConfig());
        EncryptedServerNameIndicationExtensionMessage msg = parser.parse();
        EncryptedServerNameIndicationExtensionPreparator preparator =
            new EncryptedServerNameIndicationExtensionPreparator(chooser, msg, null);

        preparator.setEsniPreparatorMode(EncryptedServerNameIndicationExtensionPreparator.EsniPreparatorMode.SERVER);
        preparator.prepareAfterParse();

        byte[] resultGroup = msg.getKeyShareEntry().getGroup().getValue();
        byte[] expectedGroup = ArrayConverter.hexStringToByteArray("001d");

        byte[] resultCipherSuite = msg.getCipherSuite().getValue();
        byte[] expectedCipherSuite = ArrayConverter.hexStringToByteArray("1301");

        byte[] resultClientPublicKey = msg.getKeyShareEntry().getPublicKey().getValue();
        byte[] expectedClientPublicKey =
            ArrayConverter.hexStringToByteArray("41f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d5400");

        int resultClientPublicKeyLength = msg.getKeyShareEntry().getPublicKeyLength().getValue();
        int expectedClientPublicKeyLength = expectedClientPublicKey.length;

        byte[] resultRecordDigest = msg.getRecordDigest().getValue();
        byte[] expectedRecordDigest =
            ArrayConverter.hexStringToByteArray("b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c");

        int resultRecordDigestLength = msg.getRecordDigestLength().getValue();
        int expectedRecordDigestLength = expectedRecordDigest.length;

        byte[] resultEncryptedSni = msg.getEncryptedSni().getValue();
        byte[] expectedEncryptedSni = ArrayConverter.hexStringToByteArray(
            "a133e3280209e18ec46ee8d37062f4df1ddc9a4d60de59fb57c284989f23fdb02da0ae115e87b57be927499ef19cf88424cd0906b915010f51a0b39be192ba10bcd6d6b47a1967439670278a433337eebd5695106e1d1ed38337e7ad71fb8f756bb527c096751da3a52604fb0859ded699e3cd2cbc47fae73819d8eb2c8dcf1eccc8502ac6cdb237e2541b85140aa83d9234e10ab0108ba81586a729bf26f95b32a9f7a89aeaecedf77fd3cdef8c58144e2a4fb359bb8a37483fdc135179793a6510d291b42b737ed9aa76b490bd6745068391831e6f2cc4370c44f0957cf932f58e8174a46dd2184a7e4950239b546a6b699b19f4e53668c2be2d2311b5965bb82ed14f22368c125a0a71acee5f06579fe9fb798f6a36092093ce32c591603c5b6b16ee");

        int resultEncryptedSniLength = msg.getEncryptedSniLength().getValue();
        int expectedEncryptedSniLength = expectedEncryptedSni.length;

        byte[] resultEsniSharedSecret = msg.getEncryptedSniComputation().getEsniSharedSecret().getValue();
        byte[] expectedEsniSharedSecret =
            ArrayConverter.hexStringToByteArray("55F22988BEC557911665246C18B744ED866D5F9DF4571C5F204E7569A2712C75");

        byte[] resultEsniMasterSecret = msg.getEncryptedSniComputation().getEsniMasterSecret().getValue();
        byte[] expectedEsniMasterSecret =
            ArrayConverter.hexStringToByteArray("BD0677ECAD9141C2B83CEF09168FFCF6DE885DA656E571D086E34CE06EEDA824");

        byte[] resultEsniContents = msg.getEncryptedSniComputation().getEsniContents().getValue();
        byte[] expectedEsniContents = ArrayConverter.hexStringToByteArray(
            "0020b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c001d002041f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d5400e6aef9c483abf499f6a1c3befa5f16f854482072a0d3d29476c51f5c3d4d5709");

        byte[] resultEsniContentsHash = msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        byte[] expectedEsniContentsHash =
            ArrayConverter.hexStringToByteArray("8106289e822aaf4ba1053ed99fcd30bb24b803c2b10f3c0d0c05892ac8332d5a");

        byte[] resultEsniKey = msg.getEncryptedSniComputation().getEsniKey().getValue();
        byte[] expectedEsniKey = ArrayConverter.hexStringToByteArray("BD005945C1C69AA9F36944C4040C5558");

        byte[] resultEsniIv = msg.getEncryptedSniComputation().getEsniIv().getValue();
        byte[] expectedEsniIv = ArrayConverter.hexStringToByteArray("41EEF7C0378F8D6D9896A15A");

        byte[] resultClientHelloKeyShare = msg.getEncryptedSniComputation().getClientHelloKeyShare().getValue();
        byte[] expectedClientHelloKeyShare = ArrayConverter.hexStringToByteArray(
            "0069001d002033f34944dd62f7d40388729b584e5eb108e29b34c739af29ec5113fb2b8d5714001700410401e31149fb03eee9a101c3660bb29db586d1a347414f0c28011a5fe4805a355d37edfec598888d76083580f0394e754a4666f9a66678c23ae2058ac2fa55a459");

        byte[] resultClientEsniInnerBytes = msg.getClientEsniInnerBytes().getValue();
        byte[] expectedClientEsniInnerBytes = ArrayConverter.hexStringToByteArray(
            "a7284c9a52f15c13644b947261774657001200000f62617a2e6578616d706c652e636f6d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

        byte[] resultNonce = msg.getClientEsniInner().getClientNonce().getValue();
        byte[] expectedNonce = ArrayConverter.hexStringToByteArray("a7284c9a52f15c13644b947261774657");

        byte[] resultServerNameListBytes = msg.getClientEsniInner().getServerNameListBytes().getValue();
        byte[] expectedServerNameListBytes =
            ArrayConverter.hexStringToByteArray("00000f62617a2e6578616d706c652e636f6d");

        int resultServerNameListLength = msg.getClientEsniInner().getServerNameListLength().getValue();
        int expectedServerNameListLength = expectedServerNameListBytes.length;

        byte[] resultPadding = msg.getClientEsniInner().getPadding().getValue();
        byte[] expectedPadding = new byte[240];

        byte resultServerNameType = msg.getClientEsniInner().getServerNameList().get(0).getServerNameType().getValue();
        byte expectedServerNameType = (byte) 0x00;

        byte[] resultServerName = msg.getClientEsniInner().getServerNameList().get(0).getServerName().getValue();
        byte[] expectedServerName = ArrayConverter.hexStringToByteArray("62617a2e6578616d706c652e636f6d");

        int resultServerNameLength =
            msg.getClientEsniInner().getServerNameList().get(0).getServerNameLength().getValue();
        int expectedServerNameLength = expectedServerName.length;

        assertArrayEquals(expectedCipherSuite, resultCipherSuite);
        assertArrayEquals(expectedGroup, resultGroup);
        assertArrayEquals(expectedClientPublicKey, resultClientPublicKey);
        assertEquals(expectedClientPublicKeyLength, resultClientPublicKeyLength);
        assertArrayEquals(expectedRecordDigest, resultRecordDigest);
        assertEquals(expectedRecordDigestLength, resultRecordDigestLength);
        assertArrayEquals(expectedEncryptedSni, resultEncryptedSni);
        assertEquals(expectedEncryptedSniLength, resultEncryptedSniLength);
        assertArrayEquals(expectedEsniSharedSecret, resultEsniSharedSecret);
        assertArrayEquals(expectedEsniMasterSecret, resultEsniMasterSecret);
        assertArrayEquals(expectedEsniContents, resultEsniContents);
        assertArrayEquals(expectedEsniContentsHash, resultEsniContentsHash);
        assertArrayEquals(expectedEsniKey, resultEsniKey);
        assertArrayEquals(expectedEsniIv, resultEsniIv);
        assertArrayEquals(expectedClientHelloKeyShare, resultClientHelloKeyShare);
        assertArrayEquals(expectedClientEsniInnerBytes, resultClientEsniInnerBytes);
        assertArrayEquals(expectedNonce, resultNonce);
        assertArrayEquals(expectedServerNameListBytes, resultServerNameListBytes);
        assertEquals(expectedServerNameListLength, resultServerNameListLength);
        assertArrayEquals(expectedPadding, resultPadding);
        assertEquals(expectedServerNameType, resultServerNameType);
        assertEquals(expectedServerNameLength, resultServerNameLength);
        assertArrayEquals(expectedServerName, resultServerName);
    }

}
