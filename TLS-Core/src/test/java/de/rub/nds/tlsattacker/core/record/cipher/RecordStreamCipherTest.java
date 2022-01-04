/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class RecordStreamCipherTest {

    private TlsContext context;
    private KeySet keySet;
    private byte[] data;

    public RecordStreamCipherTest() {
        keySet = generateKeySet(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
            ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"), new byte[1],
            ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));

        data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
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
                        RecordStreamCipher cipher = new RecordStreamCipher(context,
                            new CipherState(version, suite, KeySetGenerator.generateKeySet(context), false));
                    }
                }
            }
        }
    }

    private KeySet generateKeySet(byte[] clientWriteKey, byte[] clientWriteMacSecret, byte[] serverWriteKey,
        byte[] serverWriteMacSecret) {
        KeySet tempKeySet = new KeySet();
        tempKeySet.setClientWriteKey(clientWriteKey);
        tempKeySet.setClientWriteMacSecret(clientWriteMacSecret);
        tempKeySet.setServerWriteKey(serverWriteKey);
        tempKeySet.setServerWriteMacSecret(serverWriteMacSecret);
        return tempKeySet;
    }

    private TlsContext setContext(AliasedConnection connection, CipherSuite cipherSuite,
        ProtocolVersion protocolVersion) {
        TlsContext context = new TlsContext();
        context.setConnection(connection);
        context.setSelectedCipherSuite(cipherSuite);
        context.setSelectedProtocolVersion(protocolVersion);
        context.setSelectedCompressionMethod(CompressionMethod.NULL);
        return context;
    }

    private Record setRecord(BigInteger sequenceNumber, byte[] data, ProtocolVersion protocolVersion) {
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.setSequenceNumber(sequenceNumber);
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(protocolVersion.getValue());
        record.setProtocolMessageBytes(data);
        record.prepareComputations();
        return record;
    }

    @Test
    public void calculateMacSHA() {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.TLS10);

        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS10, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));

        assertArrayEquals(ArrayConverter.hexStringToByteArray("740b1374aac883ec9171730684b9f7bf84c56cc1"),
            cipher.calculateMac(data, context.getConnection().getLocalConnectionEndType()));

        context.setConnection(new InboundConnection());
        cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS10, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));

        assertArrayEquals(ArrayConverter.hexStringToByteArray("740b1374aac883ec9171730684b9f7bf84c56cc1"),
            cipher.calculateMac(data, context.getConnection().getLocalConnectionEndType()));
    }

    @Test
    public void calculateMacMD5() {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.TLS10);

        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS10, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));

        assertArrayEquals(ArrayConverter.hexStringToByteArray("6af39a238e82675131e6a383f801674e"),
            cipher.calculateMac(data, context.getConnection().getLocalConnectionEndType()));

        context.setConnection(new InboundConnection());
        cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS10, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));

        assertArrayEquals(ArrayConverter.hexStringToByteArray("6af39a238e82675131e6a383f801674e"),
            cipher.calculateMac(data, context.getConnection().getLocalConnectionEndType()));
    }

    @Test
    public void testEncryptSSL2SHA() throws CryptoException {
        /*
         * Please notice : SSL2 is not actually implemented in TLS-Attacker! There for, RC4 is also not implemented for
         * SSL2! Those tests are for test purposes only to check if the undefined behavior is working.
         */
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.SSL2);

        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.SSL2);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.SSL2, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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
        /*
         * Please notice : SSL2 is not actually implemented in TLS-Attacker! There for, RC4 is also not implemented for
         * SSL2! Those tests are for test purposes only to check if the undefined behavior is working.
         */
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.SSL2);

        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5");
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.SSL2);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.SSL2, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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
    public void testEncryptSSL2MD5() throws CryptoException {
        /*
         * Please notice : SSL2 is not actually implemented in TLS-Attacker! There for, RC4 is also not implemented for
         * SSL2! Those tests are for test purposes only to check if the undefined behavior is working.
         */
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.SSL2);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.SSL2);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.SSL2, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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
        /*
         * Please notice : SSL2 is not actually implemented in TLS-Attacker! There for, RC4 is also not implemented for
         * SSL2! Those tests are for test purposes only to check if the undefined behavior is working.
         */
        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2");
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.SSL2);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.SSL2);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.SSL2, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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
    public void testEncryptSSL3SHA() throws CryptoException {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.SSL3);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.SSL3);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.SSL3, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data, ProtocolVersion.SSL3);
        cipher.encrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000001160010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("2c023bf9e7c17717ed3a7b8362ba5a13e8222c36"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("010101010101010101010101010101012c023bf9e7c17717ed3a7b8362ba5a13e8222c36"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the ciphertext of the second record to ensure that the encryption is not resetted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0be5fbcbd97d3e897d1a43e229f84c0f28bd49338"),
            record2.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0be5fbcbd97d3e897d1a43e229f84c0f28bd49338"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptSSL3SHA() throws CryptoException {
        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef704c1e230428b4e84377ab0cf1f8ac98e5d9281b5");
        byte[] data2 = ArrayConverter
            .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0be5fbcbd97d3e897d1a43e229f84c0f28bd49338");
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.SSL3);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.SSL3);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.SSL3, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data2, ProtocolVersion.SSL3);
        plaintext.decrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000001160010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("2c023bf9e7c17717ed3a7b8362ba5a13e8222c36"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("010101010101010101010101010101012c023bf9e7c17717ed3a7b8362ba5a13e8222c36"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the plaintext of the second record only to ensure that the decryption is not resetted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0be5fbcbd97d3e897d1a43e229f84c0f28bd49338"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptSSL3MD5() throws CryptoException {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.SSL3);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.SSL3);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.SSL3, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data, ProtocolVersion.SSL3);
        cipher.encrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000001160010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("c69de0303fedadcb5793ca09fca60815"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101c69de0303fedadcb5793ca09fca60815"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the ciphertext of the second record to ensure that the encryption is not resetted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629a900fe91adb02a8f27815589c0384db4"),
            record2.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629a900fe91adb02a8f27815589c0384db4"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptSSL3MD5() throws CryptoException {
        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a66207d4305ec2ab84854d93aa9dffd2");
        byte[] data2 =
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629a900fe91adb02a8f27815589c0384db4");
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.SSL3);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.SSL3);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.SSL3, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data2, ProtocolVersion.SSL3);
        plaintext.decrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000001160010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("c69de0303fedadcb5793ca09fca60815"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101c69de0303fedadcb5793ca09fca60815"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the plaintext of the second record only to ensure that the decryption is not resetted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629a900fe91adb02a8f27815589c0384db4"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLSv10SHA() throws CryptoException {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.TLS10);
        /* Sets the data that should be encrypted later */
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS10);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS10, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data, ProtocolVersion.TLS10);
        cipher.encrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603010010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("040fe0b0381877b4d448462e9b30cfb6a5b87ff6"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101040fe0b0381877b4d448462e9b30cfb6a5b87ff6"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the ciphertext of the second record to ensure that the encryption is not resetted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0965267f4480ae834e8d6038f660e5557c64ec0f8"),
            record2.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0965267f4480ae834e8d6038f660e5557c64ec0f8"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv10SHA() throws CryptoException {
        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef78fa0cb307f1e7b1beef68fa824907314075768e4");
        byte[] data2 = ArrayConverter
            .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0965267f4480ae834e8d6038f660e5557c64ec0f8");
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.TLS10);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS10);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS10, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data2, ProtocolVersion.TLS10);
        plaintext.decrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603010010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("040fe0b0381877b4d448462e9b30cfb6a5b87ff6"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101040fe0b0381877b4d448462e9b30cfb6a5b87ff6"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the plaintext of the second record only to ensure that the decryption is not resetted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0965267f4480ae834e8d6038f660e5557c64ec0f8"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLSv10MD5() throws CryptoException {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.TLS10);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS10);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS10, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data, ProtocolVersion.TLS10);
        cipher.encrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603010010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("a17ccd76dd57c0891e93fe50f9d5ab9c"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101a17ccd76dd57c0891e93fe50f9d5ab9c"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the ciphertext of the second record to ensure that the encryption is not resetted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629cee1d3d74f0a47cd6e8161d0c54bee3d"),
            record2.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629cee1d3d74f0a47cd6e8161d0c54bee3d"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv10MD5() throws CryptoException {
        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7c2e042de63c508a46747511fd5df0dd5");
        byte[] data2 =
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629cee1d3d74f0a47cd6e8161d0c54bee3d");
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.TLS10);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS10);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS10, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data2, ProtocolVersion.TLS10);
        plaintext.decrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603010010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("a17ccd76dd57c0891e93fe50f9d5ab9c"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101a17ccd76dd57c0891e93fe50f9d5ab9c"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the plaintext of the second record only to ensure that the decryption is not resetted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629cee1d3d74f0a47cd6e8161d0c54bee3d"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLS11SHA() throws CryptoException {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.TLS11);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS11);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS11, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data, ProtocolVersion.TLS11);
        cipher.encrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603020010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("5b021120828d86a81449dc384bf86bc2d5baa09d"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("010101010101010101010101010101015b021120828d86a81449dc384bf86bc2d5baa09d"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the ciphertext of the second record to ensure that the encryption is not resetted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0c95f9664f29f192828d79999b6c6f123b64c1f93"),
            record2.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0c95f9664f29f192828d79999b6c6f123b64c1f93"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLS11SHA() throws CryptoException {
        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d85087a2fef711b1cd6d6bb755ed1d813dba3869");
        byte[] data2 = ArrayConverter
            .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0c95f9664f29f192828d79999b6c6f123b64c1f93");

        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.TLS11);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS11);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS11, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data2, ProtocolVersion.TLS11);
        plaintext.decrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603020010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("5b021120828d86a81449dc384bf86bc2d5baa09d"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("010101010101010101010101010101015b021120828d86a81449dc384bf86bc2d5baa09d"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the plaintext of the second record only to ensure that the decryption is not resetted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa0c95f9664f29f192828d79999b6c6f123b64c1f93"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLSv11MD5() throws CryptoException {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.TLS11);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS11);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS11, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data, ProtocolVersion.TLS11);
        cipher.encrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603020010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("d566e45299d46f13ce01839a336bac92"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101d566e45299d46f13ce01839a336bac92"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the ciphertext of the second record to ensure that the encryption is not resetted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629bafbfaf30b89e857be131c1a0ff5e933"),
            record2.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629bafbfaf30b89e857be131c1a0ff5e933"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv11MD5() throws CryptoException {
        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef70a021369e63e4556899b399dcfe0709c");
        byte[] data2 =
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629bafbfaf30b89e857be131c1a0ff5e933");
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.TLS11);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS11);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS11, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data2, ProtocolVersion.TLS11);
        plaintext.decrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603020010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("d566e45299d46f13ce01839a336bac92"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("01010101010101010101010101010101d566e45299d46f13ce01839a336bac92"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the plaintext of the second record only to ensure that the decryption is not resetted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629bafbfaf30b89e857be131c1a0ff5e933"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLS12SHA() throws CryptoException {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.TLS12);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS12);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS12, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data, ProtocolVersion.TLS12);
        cipher.encrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603030010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("f8349c55095baa9e953d9cbafa4c6dce2682ebf1"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101f8349c55095baa9e953d9cbafa4c6dce2682ebf1"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the ciphertext of the second record to ensure that the encryption is not resetted */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa06a691b117949351ea9a3d91b0772f72f457454ff"),
            record2.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa06a691b117949351ea9a3d91b0772f72f457454ff"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLS12SHA() throws CryptoException {
        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7a9419b5d3406bf2c811c3eb6c1221c47d11b5e64");
        byte[] data2 = ArrayConverter
            .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa06a691b117949351ea9a3d91b0772f72f457454ff");
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.TLS12);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS12);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS12, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data2, ProtocolVersion.TLS12);
        plaintext.decrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603030010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("f8349c55095baa9e953d9cbafa4c6dce2682ebf1"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101f8349c55095baa9e953d9cbafa4c6dce2682ebf1"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the plaintext of the second record only to ensure that the decryption is not resetted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter
                .hexStringToByteArray("265c875f34c97ea7a57406296e9c1fa06a691b117949351ea9a3d91b0772f72f457454ff"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLSv12MD5() throws CryptoException {
        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.TLS12);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS12);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS12, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data, ProtocolVersion.TLS12);
        cipher.encrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603030010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("5ce66135cf54d968a7cdca9b66eb87b7"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("010101010101010101010101010101015ce66135cf54d968a7cdca9b66eb87b7"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the ciphertext of the second record to ensure that the encryption is not resetted */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629337b7f945d095e2cd7df551b5a75c216"),
            record2.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629337b7f945d095e2cd7df551b5a75c216"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv12MD5() throws CryptoException {
        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7d89ad2bbab1e26cc5bacd4b2d9b41665");
        byte[] data2 =
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629337b7f945d095e2cd7df551b5a75c216");
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.TLS12);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS12);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS12, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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

        /* A second record is created to ensure that the internal state throughout the session will be preserved */
        Record record2 = setRecord(new BigInteger("1"), data2, ProtocolVersion.TLS12);
        plaintext.decrypt(record2);

        /*
         * tests the AuthenticatedMetaData Notice : Only the sequence number should have changed
         */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000011603030010"),
            record2.getComputations().getAuthenticatedMetaData().getValue());

        /*
         * The ClientWriteKey, ClientWriteMacSecret, should be all the same, as the were before
         */

        /* tests the mac of the second record only */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("5ce66135cf54d968a7cdca9b66eb87b7"),
            record2.getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("010101010101010101010101010101015ce66135cf54d968a7cdca9b66eb87b7"),
            record2.getComputations().getPlainRecordBytes().getValue());

        /* tests the plaintext of the second record only to ensure that the decryption is not resetted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"),
            record.getCleanProtocolMessageBytes().getValue());

        /* tests protocol message bytes encrypted of the second record */
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray("4492241d265c875f34c97ea7a5740629337b7f945d095e2cd7df551b5a75c216"),
            record2.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptTLS13SHA() throws CryptoException {
        /*
         * Please notice : RC4 is not implemented in TLS version 1.3! Those tests are for test purposes only to check if
         * the undefined behavior is working.
         */

        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.TLS13);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS13);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS13, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
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
        /*
         * Please notice : RC4 is not implemented in TLS version 1.3! Those tests are for test purposes only to check if
         * the undefined behavior is working.
         */

        byte[] data = ArrayConverter
            .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef731db362d9dec4802a6b3900993dc756e99f935fe");
        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_SHA, ProtocolVersion.TLS13);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS13, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, keySet, false));
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS13);
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
    public void testEncryptTLSv13MD5() throws CryptoException {
        /*
         * Please notice : RC4 is not implemented in TLS version 1.3! Those tests are for test purposes only to check if
         * the undefined behavior is working.
         */

        TlsContext context =
            setContext(new OutboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.TLS13);
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS13);
        RecordStreamCipher cipher = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS13, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
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
        /*
         * Please notice : RC4 is not implemented in TLS version 1.3! Those tests are for test purposes only to check if
         * the undefined behavior is working.
         */
        byte[] data =
            ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef707ca44db78fb78ab533ea7f5d1091838");

        TlsContext context =
            setContext(new InboundConnection(), CipherSuite.TLS_RSA_WITH_RC4_128_MD5, ProtocolVersion.TLS13);
        RecordStreamCipher plaintext = new RecordStreamCipher(context,
            new CipherState(ProtocolVersion.TLS13, CipherSuite.TLS_RSA_WITH_RC4_128_MD5, keySet, false));
        Record record = setRecord(new BigInteger("0"), data, ProtocolVersion.TLS13);
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
