/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Before;
import org.junit.Test;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;

@SuppressWarnings("SpellCheckingInspection")
public class EncryptedServerNameIndicationExtensionSerializerTest {

    private Chooser chooser;

    @Before
    public void setUp() {
        Config config = Config.createConfig();
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, new TlsContext(config), config);
    }

    @Test
    public void test() {
        byte[] extensionType = ExtensionType.ENCRYPTED_SERVER_NAME_INDICATION.getValue();
        int extensionLength = 366;
        byte[] cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256.getByteValue();
        byte[] namedGroup = NamedGroup.ECDH_X25519.getValue();

        byte[] recordDigest =
            ArrayConverter.hexStringToByteArray("b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c");
        int recordDigestLength = recordDigest.length;
        byte[] encryptedSni = ArrayConverter.hexStringToByteArray(
            "a133e3280209e18ec46ee8d37062f4df1ddc9a4d60de59fb57c284989f23fdb02da0ae115e87b57be927499ef19cf88424cd0906b915010f51a0b39be192ba10bcd6d6b47a1967439670278a433337eebd5695106e1d1ed38337e7ad71fb8f756bb527c096751da3a52604fb0859ded699e3cd2cbc47fae73819d8eb2c8dcf1eccc8502ac6cdb237e2541b85140aa83d9234e10ab0108ba81586a729bf26f95b32a9f7a89aeaecedf77fd3cdef8c58144e2a4fb359bb8a37483fdc135179793a6510d291b42b737ed9aa76b490bd6745068391831e6f2cc4370c44f0957cf932f58e8174a46dd2184a7e4950239b546a6b699b19f4e53668c2be2d2311b5965bb82ed14f22368c125a0a71acee5f06579fe9fb798f6a36092093ce32c591603c5b6b16ee");
        int encryptedSniLength = encryptedSni.length;
        byte[] clientPulicKey =
            ArrayConverter.hexStringToByteArray("41f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d5400");

        EncryptedServerNameIndicationExtensionMessage msg = new EncryptedServerNameIndicationExtensionMessage();
        EncryptedServerNameIndicationExtensionSerializer esniMassageSerializer =
            new EncryptedServerNameIndicationExtensionSerializer(msg);
        msg.setEsniMessageTypeConfig(EncryptedServerNameIndicationExtensionMessage.EsniMessageType.CLIENT);

        msg.getKeyShareEntry().setGroup(namedGroup);
        msg.getKeyShareEntry().setPublicKey(clientPulicKey);
        msg.getKeyShareEntry().setPublicKeyLength(clientPulicKey.length);

        msg.setExtensionType(extensionType);
        msg.setExtensionLength(extensionLength);
        msg.setCipherSuite(cipherSuite);

        msg.setRecordDigestLength(recordDigestLength);
        msg.setRecordDigest(recordDigest);
        msg.setEncryptedSniLength(encryptedSniLength);
        msg.setEncryptedSni(encryptedSni);

        byte[] resultBytes = esniMassageSerializer.serialize();
        byte[] expectedBytes = ArrayConverter.hexStringToByteArray(
            "ffce016e1301001d002041f2f4bcb69a924d3b90d815d8bbe19f5aa68926f6538626737c30bd814d54000020b045ec64136934560d15f6fde789fa515c666ea0b2979bebda671b298b6c2b9c0124a133e3280209e18ec46ee8d37062f4df1ddc9a4d60de59fb57c284989f23fdb02da0ae115e87b57be927499ef19cf88424cd0906b915010f51a0b39be192ba10bcd6d6b47a1967439670278a433337eebd5695106e1d1ed38337e7ad71fb8f756bb527c096751da3a52604fb0859ded699e3cd2cbc47fae73819d8eb2c8dcf1eccc8502ac6cdb237e2541b85140aa83d9234e10ab0108ba81586a729bf26f95b32a9f7a89aeaecedf77fd3cdef8c58144e2a4fb359bb8a37483fdc135179793a6510d291b42b737ed9aa76b490bd6745068391831e6f2cc4370c44f0957cf932f58e8174a46dd2184a7e4950239b546a6b699b19f4e53668c2be2d2311b5965bb82ed14f22368c125a0a71acee5f06579fe9fb798f6a36092093ce32c591603c5b6b16ee");

        assertArrayEquals(expectedBytes, resultBytes);
    }
}
