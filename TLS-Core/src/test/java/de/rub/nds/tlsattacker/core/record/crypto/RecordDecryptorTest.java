/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class RecordDecryptorTest {

    private RecordCipher recordCipher;
    private TlsContext context;
    private Record record;
    public RecordDecryptor decryptor;

    public RecordDecryptorTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        context = new TlsContext();
        record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
    }

    /**
     * Test of the decrypt method for TLS 1.3, of class RecordDecryptor.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testDecrypt() throws NoSuchAlgorithmException, CryptoException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13_DRAFT21);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("4B63051EABCD514D7CB6D1899F472B9F56856B01BDBC5B733FBB47269E7EBDC2"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("ACC9DB33EE0968FAE7E06DAA34D642B146092CE7F9C9CF47670C66A0A6CE1C8C"));
        context.setConnection(new OutboundConnection());
        record.setProtocolMessageBytes(ArrayConverter
                .hexStringToByteArray("1BB3293A919E0D66F145AE830488E8D89BE5EC16688229"));
        record.setLength(record.getProtocolMessageBytes().getValue().length);
        context.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        recordCipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);
        // assertTrue(record.getContentMessageType() ==
        // ProtocolMessageType.HANDSHAKE);
        assertTrue(record.getCleanProtocolMessageBytes().getValue().length == 6);
        assertArrayEquals(record.getCleanProtocolMessageBytes().getValue(),
                ArrayConverter.hexStringToByteArray("080000020000"));
    }

    @Test
    public void testDecryptTLS12Block() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

    }

    @Test
    public void testDecryptTLS12Camellia() throws NoSuchAlgorithmException, CryptoException {
        context.setRandom(new TestRandomData(ArrayConverter
                .hexStringToByteArray("16B406CF7A489CA985883AEDA28D34E34ED3256F1B380C692B962DF892180C5A")));
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA);
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("EC28993D8B3F3D81D626C3B419C34547373C5EA49C4A727790C59892AACFF4FEF0945725996013C65581110889D019DE"));
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("DA5BA97EAC47D864C1041B542885F0CD20F05F7F3E0929FBE38D2A72497D5A53"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("2488DFEE45765EEF369F30AFE356B9463624C6D617503AAB6B592B8CBDB55AB2"));
        context.setConnection(new InboundConnection());

        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(ArrayConverter
                .hexStringToByteArray("16B406CF7A489CA985883AEDA28D34E3AB1B66A1C376C1F354607CFDA1739D9B60D30776152207B1988604FBCF75E6BC370ADE1EE684CAE9B0801AAE50CC2EFA"));

        recordCipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);
        assertArrayEquals(ArrayConverter.hexStringToByteArray("16B406CF7A489CA985883AEDA28D34E3"), record
                .getComputations().getInitialisationVector().getValue());
        assertEquals(11, (long) record.getComputations().getPaddingLength().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030010"), record.getComputations()
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("27BE1FB155ACFBF9E78D0C259E693123"), record
                .getComputations().getNonMetaDataMaced().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11EBB8BC910709D40FA3612679F0CE5DB12575FD"), record
                .getComputations().getMac().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("27BE1FB155ACFBF9E78D0C259E69312311EBB8BC910709D40FA3612679F0CE5DB12575FD"),
                record.getComputations().getUnpaddedRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0B0B0B0B0B0B0B0B0B0B0B0B"), record.getComputations()
                .getPadding().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("27BE1FB155ACFBF9E78D0C259E69312311EBB8BC910709D40FA3612679F0CE5DB12575FD0B0B0B0B0B0B0B0B0B0B0B0B"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS12Stream() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

    }

    @Test
    public void testDecryptTLS12AEAD() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

    }

    @Test
    public void testDecryptTLS10Block() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

    }

    @Test
    public void testDecryptTLS10Stream() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

    }

    @Test
    public void testDecryptTLS12BlockEncrypthThenMac() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

    }

    @Test
    public void testDecryptTLS12StreamEncrypthThenMac() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

    }

    @Test
    public void testDecryptTLS12AEADEncrypthThenMac() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

    }

}
