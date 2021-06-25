/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class RecordStreamCipherTest {

    private TlsContext context;

    public RecordStreamCipherTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
    }

    // TODO check why cipher.contains("WITH_NULL") in
    // AlgorithmResolver.getCipherType(suite) is always associated with STREAM
    @Test
    public void testConstructors() throws NoSuchAlgorithmException, CryptoException {
        // This test just checks that the init() method will not break
        context.setClientRandom(new byte[] { 0 });
        context.setServerRandom(new byte[] { 0 });
        context.setMasterSecret(new byte[] { 0 });
        AliasedConnection[] connections = new AliasedConnection[] { new InboundConnection(), new OutboundConnection() };
        for (CipherSuite suite : CipherSuite.values()) {
            if (!suite.isGrease() && !suite.isSCSV() && !suite.name().contains("WITH_NULL_NULL")
                && !suite.name().contains("CHACHA20_POLY1305") && !suite.name().contains("RABBIT")
                && AlgorithmResolver.getCipherType(suite) == CipherType.STREAM && !suite.name().contains("FORTEZZA")
                && !suite.name().contains("ARIA")) {
                context.setSelectedCipherSuite(suite);
                for (AliasedConnection con : connections) {
                    context.setConnection(con);
                    for (ProtocolVersion version : ProtocolVersion.values()) {
                        if (version == ProtocolVersion.SSL2 || version.isTLS13()) {
                            continue;
                        }
                        if (!suite.isSupportedInProtocol(version)) {
                            continue;
                        }
                        context.setSelectedProtocolVersion(version);
                        @SuppressWarnings("unused")
                        RecordStreamCipher cipher =
                            new RecordStreamCipher(context, KeySetGenerator.generateKeySet(context));
                    }
                }
            }
        }
    }

    @Test
    public void calculateMacSHA() throws CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        /**/
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("740b1374aac883ec9171730684b9f7bf84c56cc1"),
            cipher.calculateMac(data, context.getConnection().getLocalConnectionEndType()));

        context.setConnection(new InboundConnection());
        cipher = new RecordStreamCipher(context, keySet);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("740b1374aac883ec9171730684b9f7bf84c56cc1"),
            cipher.calculateMac(data, context.getConnection().getLocalConnectionEndType()));
    }

    @Test
    public void calculateMacMD5() throws CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);

        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("6af39a238e82675131e6a383f801674e"),
            cipher.calculateMac(data, context.getConnection().getLocalConnectionEndType()));

        context.setConnection(new InboundConnection());
        cipher = new RecordStreamCipher(context, keySet);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("6af39a238e82675131e6a383f801674e"),
            cipher.calculateMac(data, context.getConnection().getLocalConnectionEndType()));
    }

    @Test
    public void testEncryptSSL2SHA() throws CryptoException, NoSuchAlgorithmException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL2);
        context.setSelectedCompressionMethod(CompressionMethod.NULL);

        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.SSL2.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("618C472957C9EA333ED9437FBC24F8701801A4A9"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101618C472957C9EA333ED9437FBC24F8701801A4A9"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptSSL2SHA() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL2);

        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.SSL2.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("618C472957C9EA333ED9437FBC24F8701801A4A9"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101618C472957C9EA333ED9437FBC24F8701801A4A9"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptSSL2MD5() throws CryptoException, NoSuchAlgorithmException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL2);
        context.setSelectedCompressionMethod(CompressionMethod.NULL);

        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.SSL2.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("C32FA2CD251C661C8D26BE230933CE2C"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101C32FA2CD251C661C8D26BE230933CE2C"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptSSL2MD5() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL2);

        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.SSL2.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("C32FA2CD251C661C8D26BE230933CE2C"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101C32FA2CD251C661C8D26BE230933CE2C"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptSSL3SHA() throws CryptoException, NoSuchAlgorithmException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL3);
        context.setSelectedCompressionMethod(CompressionMethod.NULL);

        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.SSL3.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("618C472957C9EA333ED9437FBC24F8701801A4A9"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101618C472957C9EA333ED9437FBC24F8701801A4A9"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptSSL3SHA() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL3);

        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.SSL3.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("618C472957C9EA333ED9437FBC24F8701801A4A9"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101618C472957C9EA333ED9437FBC24F8701801A4A9"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptSSL3MD5() throws CryptoException, NoSuchAlgorithmException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL3);
        context.setSelectedCompressionMethod(CompressionMethod.NULL);

        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.SSL3.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("C32FA2CD251C661C8D26BE230933CE2C"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101C32FA2CD251C661C8D26BE230933CE2C"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptSSL3MD5() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL3);

        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.SSL3.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("C32FA2CD251C661C8D26BE230933CE2C"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101C32FA2CD251C661C8D26BE230933CE2C"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLSv10SHA() throws CryptoException, NoSuchAlgorithmException {
        /* Outbound for Clients, Inbound for Servers */
        context.setConnection(new OutboundConnection());
        /* Sets the Ciphersuit for the Handshake */
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        /* Sets the SSL/TLS version */
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);

        /* Sets the data that should be encrypted later */
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();

        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));

        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();

        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("eaed6e296a5cdface7557c18873e42ea42c44df8"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101eaed6e296a5cdface7557c18873e42ea42c44df8"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef78fa0cb307f1e7b1beef68fa824907314075768e4"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef78fa0cb307f1e7b1beef68fa824907314075768e4"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv10SHA() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);

        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef78fa0cb307f1e7b1beef68fa824907314075768e4");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("eaed6e296a5cdface7557c18873e42ea42c44df8"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101eaed6e296a5cdface7557c18873e42ea42c44df8"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef78fa0cb307f1e7b1beef68fa824907314075768e4"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLSv10MD5() throws CryptoException, NoSuchAlgorithmException {
        /* Outbound for Clients, Inbound for Servers */
        context.setConnection(new OutboundConnection());
        /* Sets the Ciphersuit for the Handshake */
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        /* Sets the SSL/TLS version */
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);

        /* Sets the data that should be encrypted later */
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();

        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));

        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();

        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("a7ade7c77687ac136ee4a2af76713c2b"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101a7ade7c77687ac136ee4a2af76713c2b"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7c2e042de63c508a46747511fd5df0dd5"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7c2e042de63c508a46747511fd5df0dd5"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv10MD5() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);

        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7c2e042de63c508a46747511fd5df0dd5");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("a7ade7c77687ac136ee4a2af76713c2b"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101a7ade7c77687ac136ee4a2af76713c2b"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7c2e042de63c508a46747511fd5df0dd5"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLS11SHA() throws CryptoException, NoSuchAlgorithmException {
        /* Outbound for Clients, Inbound for Servers */
        context.setConnection(new OutboundConnection());
        /* Sets the Ciphersuit for the Handshake */
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        /* Sets the SSL/TLS version */
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);

        /* Sets the data that should be encrypted later */
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();

        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));

        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();

        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("bd1d22bbebb5b506c4ce9807f6432c7f78291d75"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101bd1d22bbebb5b506c4ce9807f6432c7f78291d75"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d85087a2fef711b1cd6d6bb755ed1d813dba3869"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d85087a2fef711b1cd6d6bb755ed1d813dba3869"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLS11SHA() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);

        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d85087a2fef711b1cd6d6bb755ed1d813dba3869");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("bd1d22bbebb5b506c4ce9807f6432c7f78291d75"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101bd1d22bbebb5b506c4ce9807f6432c7f78291d75"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d85087a2fef711b1cd6d6bb755ed1d813dba3869"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLSv11MD5() throws CryptoException, NoSuchAlgorithmException {
        /* Outbound for Clients, Inbound for Servers */
        context.setConnection(new OutboundConnection());
        /* Sets the Ciphersuit for the Handshake */
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        /* Sets the SSL/TLS version */
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);

        /* Sets the data that should be encrypted later */
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();

        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));

        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();

        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("6f4fb670f37ce1e18038ca2d6c4e4162"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("010101010101010101010101010101016f4fb670f37ce1e18038ca2d6c4e4162"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef70a021369e63e4556899b399dcfe0709c"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef70a021369e63e4556899b399dcfe0709c"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv11MD5() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);

        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef70a021369e63e4556899b399dcfe0709c");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603020010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("6f4fb670f37ce1e18038ca2d6c4e4162"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("010101010101010101010101010101016f4fb670f37ce1e18038ca2d6c4e4162"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef70a021369e63e4556899b399dcfe0709c"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLS12SHA() throws CryptoException, NoSuchAlgorithmException {
        /* Outbound for Clients, Inbound for Servers */
        context.setConnection(new OutboundConnection());
        /* Sets the Ciphersuit for the Handshake */
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        /* Sets the SSL/TLS version */
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);

        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();

        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));

        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();

        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("cc0c3e4421441b9b88bfcd06628c2db994887b78"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101cc0c3e4421441b9b88bfcd06628c2db994887b78"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a9419b5d3406bf2c811c3eb6c1221c47d11b5e64"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a9419b5d3406bf2c811c3eb6c1221c47d11b5e64"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLS12SHA() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);

        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a9419b5d3406bf2c811c3eb6c1221c47d11b5e64");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("cc0c3e4421441b9b88bfcd06628c2db994887b78"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101cc0c3e4421441b9b88bfcd06628c2db994887b78"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a9419b5d3406bf2c811c3eb6c1221c47d11b5e64"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLSv12MD5() throws CryptoException, NoSuchAlgorithmException {
        /* Outbound for Clients, Inbound for Servers */
        context.setConnection(new OutboundConnection());
        /* Sets the Ciphersuit for the Handshake */
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        /* Sets the SSL/TLS version */
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);

        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();

        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));

        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();

        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("bdd777a2be5c827b520f27027a1a279b"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101bdd777a2be5c827b520f27027a1a279b"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d89ad2bbab1e26cc5bacd4b2d9b41665"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d89ad2bbab1e26cc5bacd4b2d9b41665"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv12MD5() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);

        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d89ad2bbab1e26cc5bacd4b2d9b41665");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030010"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("bdd777a2be5c827b520f27027a1a279b"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101bdd777a2be5c827b520f27027a1a279b"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d89ad2bbab1e26cc5bacd4b2d9b41665"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLS13SHA() throws CryptoException, NoSuchAlgorithmException {
        /* Outbound for Clients, Inbound for Servers */
        context.setConnection(new OutboundConnection());
        /* Sets the Ciphersuit for the Handshake */
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        /* Sets the SSL/TLS version */
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);

        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();

        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();

        record.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("1603040024"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("5496933488aeecb5af1063b930724490dc6a10e2"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("010101010101010101010101010101015496933488aeecb5af1063b930724490dc6a10e2"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef731db362d9dec4802a6b3900993dc756e99f935fe"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef731db362d9dec4802a6b3900993dc756e99f935fe"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLS13SHA() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);

        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef731db362d9dec4802a6b3900993dc756e99f935fe");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        record.setProtocolMessageBytes(data);
        record.setLength(36);
        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("1603040024"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("5496933488aeecb5af1063b930724490dc6a10e2"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("010101010101010101010101010101015496933488aeecb5af1063b930724490dc6a10e2"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef731db362d9dec4802a6b3900993dc756e99f935fe"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLSv13MD5() throws CryptoException, NoSuchAlgorithmException {
        /* Outbound for Clients, Inbound for Servers */
        context.setConnection(new OutboundConnection());
        /* Sets the Ciphersuit for the Handshake */
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        /* Sets the SSL/TLS version */
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);

        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();

        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));

        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]); // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();

        record.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        record.setCleanProtocolMessageBytes(data);

        cipher.encrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("1603040020"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("6287e1c26db9dc1c5a9d544572a729c6"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("010101010101010101010101010101016287e1c26db9dc1c5a9d544572a729c6"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef707ca44db78fb78ab533ea7f5d1091838"),
            record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef707ca44db78fb78ab533ea7f5d1091838"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv13MD5() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);

        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef707ca44db78fb78ab533ea7f5d1091838");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context, keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        record.setProtocolMessageBytes(data);
        record.setLength(32);
        plaintext.decrypt(record);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("1603040020"),
            record.getComputations().getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
            record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("6287e1c26db9dc1c5a9d544572a729c6"),
            record.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("010101010101010101010101010101016287e1c26db9dc1c5a9d544572a729c6"),
            record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef707ca44db78fb78ab533ea7f5d1091838"),
            record.getProtocolMessageBytes().getValue());
    }
}