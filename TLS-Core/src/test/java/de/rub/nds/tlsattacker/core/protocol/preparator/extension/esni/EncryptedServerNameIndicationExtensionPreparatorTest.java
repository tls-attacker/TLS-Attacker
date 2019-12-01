/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension.esni;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import org.junit.Before;
import org.junit.Test;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.ForgivingX25519Curve;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.PublicKeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptedServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;

public class EncryptedServerNameIndicationExtensionPreparatorTest {

    private Chooser chooser;

    @Before
    public void setUp() {
        Config config = Config.createConfig();
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, new TlsContext(config), config);
    }

    @Test
    public void test() {
        // Def Parameters:
        byte[] cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256.getByteValue();
        String hostname = "baz.example.com";
        byte nameType = (byte) 0x00;

        byte[] namedGroup = NamedGroup.ECDH_X25519.getValue();

        byte[] keyShareEntry = ArrayConverter
                .hexStringToByteArray("41f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d5400");

        byte[] sk = ArrayConverter
                .hexStringToByteArray("b0b658b2287a55d9c261bb3feb0c55954be29366eb353b54f986acaa62f81e5A");
        byte[] pk = ArrayConverter
                .hexStringToByteArray("41f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d5400");

        byte[] clientHelloRandom = ArrayConverter
                .hexStringToByteArray("e6aef9c483abf499f6a1c3befa5f16f854482072a0d3d29476c51f5c3d4d5709");
        byte[] keyShareClientHello = ArrayConverter
                .hexStringToByteArray("0069001d002033f34944dd62f7d40388729b584e5eb108e29b34c739af29ec5113fb2b8d5714001700410401e31149fb03eee9a101c3660bb29db586d1a347414f0c28011a5fe4805a355d37edfec598888d76083580f0394e754a4666f9a66678c23ae2058ac2fa55a459");
        byte[] recordBytes = ArrayConverter
                .hexStringToByteArray("ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412000213010104000000005dcc3a45000000005dda12050000");

        // Set Parameters:
        EncryptedServerNameIndicationExtensionMessage msg = new EncryptedServerNameIndicationExtensionMessage();
        EncryptedServerNameIndicationExtensionSerializer serializer = new EncryptedServerNameIndicationExtensionSerializer(
                msg);
        EncryptedServerNameIndicationExtensionPreparator preparator = new EncryptedServerNameIndicationExtensionPreparator(
                chooser, msg, serializer);

        ServerNamePair pair = new ServerNamePair();
        pair.setServerNameTypeConfig(nameType);
        pair.setServerNameConfig(hostname.getBytes(StandardCharsets.UTF_8));
        msg.getClientEsniInner().getServerNameList().add(pair);

        msg.setCipherSuiteConfig(cipherSuite);
        msg.getKeyShareEntry().setNamedGroup(namedGroup);
        msg.getKeyShareEntry().setKeyExchange(keyShareEntry);

        msg.getEncryptedSniComputation().setSk(sk);
        msg.getEncryptedSniComputation().setPk(pk);
        msg.getEncryptedSniComputation().setClientHelloRandom(clientHelloRandom);
        msg.getEncryptedSniComputation().setClientHelloKeyShare(keyShareClientHello);
        msg.getEncryptedSniComputation().setRecordBytes(recordBytes);

        // Compare results and expectations:
        preparator.prepare();

        byte[] resultClientEsniInnerBytes = msg.getClientEsniInnerBytes().getValue();
        byte[] expectedClientEsniInnerBytes = ArrayConverter
                .hexStringToByteArray("A7284C9A52F15C13644B947261774657001200000F62617A2E6578616D706C652E636F6D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

        byte[] resultRecordDigest = msg.getRecordDigest().getValue();
        byte[] expectedRecordDigest = ArrayConverter
                .hexStringToByteArray("b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c");

        int resultRecordDigestLength = msg.getRecordDigestLength().getValue();
        int expectedRecordDigestLength = 256 / 8;

        byte[] resultContents = msg.getEncryptedSniComputation().getEsniContents().getValue();
        byte[] expectedContents = ArrayConverter
                .hexStringToByteArray("0020b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c001d002041f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d5400e6aef9c483abf499f6a1c3befa5f16f854482072a0d3d29476c51f5c3d4d5709");

        byte[] resultContentsHash = msg.getEncryptedSniComputation().getEsniContentsHash().getValue();
        byte[] expectedContentsHash = ArrayConverter
                .hexStringToByteArray("8106289e822aaf4ba1053ed99fcd30bb24b803c2b10f3c0d0c05892ac8332d5a");

        byte[] resultSharedSecret = msg.getEncryptedSniComputation().getSharedSecret().getValue();
        byte[] expectedSharedSecret = ArrayConverter
                .hexStringToByteArray("55F22988BEC557911665246C18B744ED866D5F9DF4571C5F204E7569A2712C75");

        byte[] resultMasterSecret = msg.getEncryptedSniComputation().getMasterSecret().getValue();
        byte[] expectedMasterSecret = ArrayConverter
                .hexStringToByteArray("BD0677ECAD9141C2B83CEF09168FFCF6DE885DA656E571D086E34CE06EEDA824");

        byte[] resultKey = msg.getEncryptedSniComputation().getKey().getValue();
        byte[] expectedKey = ArrayConverter.hexStringToByteArray("BD005945C1C69AA9F36944C4040C5558");

        byte[] resultEncryptedSni = msg.getEncryptedSni().getValue();
        byte[] expectedEncryptedSni = ArrayConverter
                .hexStringToByteArray("a133e3280209e18ec46ee8d37062f4df1ddc9a4d60de59fb57c284989f23fdb02da0ae115e87b57be927499ef19cf88424cd0906b915010f51a0b39be192ba10bcd6d6b47a1967439670278a433337eebd5695106e1d1ed38337e7ad71fb8f756bb527c096751da3a52604fb0859ded699e3cd2cbc47fae73819d8eb2c8dcf1eccc8502ac6cdb237e2541b85140aa83d9234e10ab0108ba81586a729bf26f95b32a9f7a89aeaecedf77fd3cdef8c58144e2a4fb359bb8a37483fdc135179793a6510d291b42b737ed9aa76b490bd6745068391831e6f2cc4370c44f0957cf932f58e8174a46dd2184a7e4950239b546a6b699b19f4e53668c2be2d2311b5965bb82ed14f22368c125a0a71acee5f06579fe9fb798f6a36092093ce32c591603c5b6b16ee");

        assertArrayEquals(expectedClientEsniInnerBytes, resultClientEsniInnerBytes);
        assertArrayEquals(expectedRecordDigest, resultRecordDigest);
        assertEquals(expectedRecordDigestLength, resultRecordDigestLength);
        assertArrayEquals(expectedContents, resultContents);
        assertArrayEquals(expectedContentsHash, resultContentsHash);
        assertArrayEquals(expectedSharedSecret, resultSharedSecret);
        assertArrayEquals(expectedMasterSecret, resultMasterSecret);
        assertArrayEquals(expectedKey, resultKey);
        assertArrayEquals(resultEncryptedSni, expectedEncryptedSni);

    }

}
