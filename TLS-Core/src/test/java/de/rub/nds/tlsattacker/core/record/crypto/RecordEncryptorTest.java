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
import de.rub.nds.modifiablevariable.util.BadFixedRandom;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordStreamCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Random;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.TestRandomData;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class RecordEncryptorTest {

    private RecordCipher recordCipher;
    private TlsContext context;
    private Record record;
    public RecordEncryptor encryptor;

    public RecordEncryptorTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        context = new TlsContext();
        record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setSequenceNumber(BigInteger.ZERO);
    }

    /**
     * Test of the encrypt method for TLS 1.3, of class RecordEncryptor.
     */
    @Test
    public void testEncryptTLS13() throws NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setEncryptActive(true);
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("4B63051EABCD514D7CB6D1899F472B9F56856B01BDBC5B733FBB47269E7EBDC2"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("ACC9DB33EE0968FAE7E06DAA34D642B146092CE7F9C9CF47670C66A0A6CE1C8C"));
        context.setConnectionEnd(new ServerConnectionEnd());
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setPaddingLength(0);
        recordCipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);
        assertTrue(record.getProtocolMessageBytes().getValue().length == 23);
        assertArrayEquals(record.getProtocolMessageBytes().getValue(),
                ArrayConverter.hexStringToByteArray("1BB3293A919E0D66F145AE830488E8D89BE5EC16688229"));
    }

    @Test
    public void testEncryptTLS12Block() throws NoSuchAlgorithmException {
        Random random = new TestRandomData(
                ArrayConverter.hexStringToByteArray("91A3B6AAA2B64D126E5583B04C113259C948E1D0B39BB9560CD5409B6ECAFEDB"));//
        // explicit
        // IV's
        context.setRandom(random);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("4F04374497508D697BE7E39983B26E77DB6C60178C9B47D437E4E37F910923ECD779FDBC11D55B69E311A58CBF2FDC8C"));
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("EB9DB77B60B420BB3851D9D47ACB933DBE70399BF6C92DA33AF01D4FB770E98C"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("59D5EAEF4D34A1FC14E3417E6ED24FD5FB39B5009D9CB3181CECDAFB46D1EBD4"));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("1400000CB692015BE123B8364314FE1C"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        recordCipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030010"), record
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1400000CB692015BE123B8364314FE1C"), record
                .getNonMetaDataMaced().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("BD527A01EDCA68BF5A7918C190942A9AECA971CA"), record
                .getMac().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CB692015BE123B8364314FE1CBD527A01EDCA68BF5A7918C190942A9AECA971CA"),
                record.getUnpaddedRecordBytes().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0B0B0B0B0B0B0B0B0B0B0B0B"), record.getPadding()
                .getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CB692015BE123B8364314FE1CBD527A01EDCA68BF5A7918C190942A9AECA971CA0B0B0B0B0B0B0B0B0B0B0B0B"),
                record.getPlainRecordBytes().getValue());
        assertNull(record.getInitialisationVector());
        assertTrue(12 == record.getPaddingLength().getValue());
        assertArrayEquals(
                record.getProtocolMessageBytes().getValue(),
                ArrayConverter
                        .hexStringToByteArray("91A3B6AAA2B64D126E5583B04C1132591010FF2EE70446DA41EA4D83FE2DA55ADFAB9A17F5ACED2BA0068A95B30825119705383687AE8F0DC1BFC17E6D407CF9"));
    }

    @Test
    public void testEncryptTLS12Stream() throws NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        recordCipher = new RecordStreamCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);

    }

    @Test
    public void testEncryptTLS12AEAD() throws NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        recordCipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);

    }

    @Test
    public void testEncryptTLS10Block() throws NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        recordCipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);

    }

    @Test
    public void testEncryptTLS10Stream() throws NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        recordCipher = new RecordStreamCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);

    }

    @Test
    public void testEncryptTLS12BlockEncrypthThenMac() throws NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        recordCipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);

    }

    @Test
    public void testEncryptTLS12StreamEncrypthThenMac() throws NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        recordCipher = new RecordStreamCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);

    }

    @Test
    public void testEncryptTLS12AEADEncrypthThenMac() throws NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        recordCipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);
    }

    public void testEncrypthTLS12NullCipher() {

    }

    public void testEncrypthTLS10NullCipher() {

    }
}
