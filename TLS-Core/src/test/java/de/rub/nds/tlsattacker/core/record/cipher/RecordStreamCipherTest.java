/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
    // AlgorithmResolver.getCipherType(suite) is always assocaited with STREAM
    @Test
    public void testConstructors() throws NoSuchAlgorithmException, CryptoException {
        // This test just checks that the init() method will not break
        context.setClientRandom(new byte[]{0});
        context.setServerRandom(new byte[]{0});
        context.setMasterSecret(new byte[]{0});
        AliasedConnection[] connections = new AliasedConnection[]{new InboundConnection(), new OutboundConnection()};
        for (CipherSuite suite : CipherSuite.values()) {
            if (!suite.isGrease() && !suite.isSCSV() && !suite.name().contains("WITH_NULL_NULL")
                    && !suite.name().contains("CHACHA20_POLY1305") && !suite.name().contains("RABBIT")
                    && AlgorithmResolver.getCipherType(suite) == CipherType.STREAM
                    && !suite.name().contains("FORTEZZA") && !suite.name().contains("ARIA")) {
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
                                KeySetGenerator.generateKeySet(context));
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

        byte[] data = ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter
                .hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context,
                keySet);

        assertArrayEquals(ArrayConverter
                        .hexStringToByteArray("740b1374aac883ec9171730684b9f7bf84c56cc1"),
                cipher.calculateMac(data, context.getTalkingConnectionEndType()));

        context.setConnection(new InboundConnection());
        cipher = new RecordStreamCipher(context, keySet);

        assertArrayEquals(ArrayConverter
                        .hexStringToByteArray("740b1374aac883ec9171730684b9f7bf84c56cc1"),
                cipher.calculateMac(data, context.getTalkingConnectionEndType()));
    }

    @Test
    public void calculateMacMD5() throws CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);

        byte[] data = ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter
                .hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context,
                keySet);

        assertArrayEquals(ArrayConverter
                        .hexStringToByteArray("6af39a238e82675131e6a383f801674e"),
                cipher.calculateMac(data, context.getTalkingConnectionEndType()));

        context.setConnection(new InboundConnection());
        cipher = new RecordStreamCipher(context, keySet);

        assertArrayEquals(ArrayConverter
                        .hexStringToByteArray("6af39a238e82675131e6a383f801674e"),
                cipher.calculateMac(data, context.getTalkingConnectionEndType()));
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
        byte[] data = ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101");

        /* Sets a new keySet
        a keySet contains the negotiated keys out of the pseudorandom bit stream*/
        KeySet keySet = new KeySet();
        /* Since we're on the client side we're setting EncWriteClient and MacWriteClient only
         * Note that we have to consider the key length for the rc4 cipher since it can be used with different lengths
         * rc4 can have a key length from 40 bit up to 256 bit
         * First we're generating the keys for RC4 with SHA*/
        keySet.setClientWriteKey(ArrayConverter
                .hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        /*The key length for HMAC-SHA are 20 bytes*/
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);           // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]);           // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]);         // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]);   // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context,
                keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        /* sequence numbers are 64-bits long */
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setCleanProtocolMessageBytes(data);

        /* the cipher is computed over the plaintext(data) and the mac
         * the mac is computed over the AuthenticatedMetaData + plaintext + LocalConnectionEndType*/
        cipher.encrypt(record);

        /* tests the meta data of the record
         * the MAC is computed from the MAC secret,
         * the sequence number,                  00 00 00 00 00 00 00 00 ---+
         * the type field,                                            16 ---+
         * the protocol version,                                   03 01 ---+---> authenticated meta data ---+
         * the message length,                                     00 10 ---+                                |
         * the message contents,                          01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 ---+---> HMAC ---> hash
         * and two fixed character strings                                                  opad and ipad ---+
         *  .*/
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010010"), record.getComputations()
                .getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
                record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
                record.getComputations().getMacKey().getValue());

        /* tests the mac only*/
        assertArrayEquals(ArrayConverter.hexStringToByteArray("eaed6e296a5cdface7557c18873e42ea42c44df8"), record
                .getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101eaed6e296a5cdface7557c18873e42ea42c44df8"),
                record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(ArrayConverter
                        .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef78fa0cb307f1e7b1beef68fa824907314075768e4"),
                record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef78fa0cb307f1e7b1beef68fa824907314075768e4"),
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
        keySet.setClientWriteKey(ArrayConverter
                .hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter
                .hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context,
                keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        /* tests the meta data of the record
         * the MAC is computed from the MAC secret,
         * the sequence number,                  00 00 00 00 00 00 00 00 ---+
         * the type field,                                            16 ---+
         * the protocol version,                                   03 01 ---+---> authenticated meta data ---+
         * the message length,                                     00 10 ---+                                |
         * the message contents,                          01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 ---+---> HMAC ---> hash
         * and two fixed character strings                                                  opad and ipad ---+
         *  .*/
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010010"), record.getComputations()
                .getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
                record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
                record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter
                        .hexStringToByteArray("01010101010101010101010101010101"),
                record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only*/
        assertArrayEquals(ArrayConverter.hexStringToByteArray("eaed6e296a5cdface7557c18873e42ea42c44df8"), record
                .getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101eaed6e296a5cdface7557c18873e42ea42c44df8"),
                record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef78fa0cb307f1e7b1beef68fa824907314075768e4"),
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
        byte[] data = ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101");

        /* Sets a new keySet
        a keySet contains the negotiated keys out of the pseudorandom bit stream*/
        KeySet keySet = new KeySet();
        /* Since we're on the client side we're setting EncWriteClient and MacWriteClient only
         * Note that we have to consider the key length for the rc4 cipher since it can be used with different lengths
         * rc4 can have a key length from 40 bit up to 256 bit
         * First we're generating the keys for RC4 with SHA*/
        keySet.setClientWriteKey(ArrayConverter
                .hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        /*The key length for HMAC-SHA are 20 bytes*/
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);           // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]);           // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]);         // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]);   // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context,
                keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        /* sequence numbers are 64-bits long */
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setCleanProtocolMessageBytes(data);

        /* the cipher is computed over the plaintext(data) and the mac
         * the mac is computed over the AuthenticatedMetaData + plaintext + LocalConnectionEndType*/
        cipher.encrypt(record);

        /* tests the meta data of the record
         * the MAC is computed from the MAC secret,
         * the sequence number,                  00 00 00 00 00 00 00 00 ---+
         * the type field,                                            16 ---+
         * the protocol version,                                   03 01 ---+---> authenticated meta data ---+
         * the message length,                                     00 10 ---+                                |
         * the message contents,                          01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 ---+---> HMAC ---> hash
         * and two fixed character strings                                                  opad and ipad ---+
         *  .*/
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010010"), record.getComputations()
                .getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
                record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
                record.getComputations().getMacKey().getValue());

        /* tests the mac only*/
        assertArrayEquals(ArrayConverter.hexStringToByteArray("a7ade7c77687ac136ee4a2af76713c2b"), record
                .getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101a7ade7c77687ac136ee4a2af76713c2b"),
                record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(ArrayConverter
                        .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7c2e042de63c508a46747511fd5df0dd5"),
                record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7c2e042de63c508a46747511fd5df0dd5"),
                record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptTLSv10MD5() throws CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);

        byte[] data = ArrayConverter
                .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7c2e042de63c508a46747511fd5df0dd5");

        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter
                .hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        keySet.setClientWriteMacSecret(ArrayConverter
                .hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);
        keySet.setServerWriteIv(new byte[8]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); // ServerSide is not used

        RecordStreamCipher plaintext = new RecordStreamCipher(context,
                keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setProtocolMessageBytes(data);

        plaintext.decrypt(record);

        /* tests the meta data of the record
         * the MAC is computed from the MAC secret,
         * the sequence number,                  00 00 00 00 00 00 00 00 ---+
         * the type field,                                            16 ---+
         * the protocol version,                                   03 01 ---+---> authenticated meta data ---+
         * the message length,                                     00 10 ---+                                |
         * the message contents,                          01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 ---+---> HMAC ---> hash
         * and two fixed character strings                                                  opad and ipad ---+
         *  .*/
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010010"), record.getComputations()
                .getAuthenticatedMetaData().getValue());

        /* tests the decryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
                record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
                record.getComputations().getMacKey().getValue());

        /* tests the decryption only */
        assertArrayEquals(ArrayConverter
                        .hexStringToByteArray("01010101010101010101010101010101"),
                record.getCleanProtocolMessageBytes().getValue());

        /* tests the mac only*/
        assertArrayEquals(ArrayConverter.hexStringToByteArray("a7ade7c77687ac136ee4a2af76713c2b"), record
                .getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101a7ade7c77687ac136ee4a2af76713c2b"),
                record.getComputations().getPlainRecordBytes().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef7c2e042de63c508a46747511fd5df0dd5"),
                record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptSSL310SHA() throws CryptoException, NoSuchAlgorithmException {
        /* Outbound for Clients, Inbound for Servers */
        context.setConnection(new OutboundConnection());
        /* Sets the Ciphersuit for the Handshake */
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        /* Sets the SSL/TLS version */
        context.setSelectedProtocolVersion(ProtocolVersion.SSL3);

        /* Sets the data that should be encrypted later */
        byte[] data = ArrayConverter
                .hexStringToByteArray("01010101010101010101010101010101");

        /* Sets a new keySet
        a keySet contains the negotiated keys out of the pseudorandom bit stream*/
        KeySet keySet = new KeySet();
        /* Since we're on the client side we're setting EncWriteClient and MacWriteClient only
         * Note that we have to consider the key length for the rc4 cipher since it can be used with different lengths
         * rc4 can have a key length from 40 bit up to 256 bit
         * First we're generating the keys for RC4 with SHA*/
        keySet.setClientWriteKey(ArrayConverter
                .hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"));
        /*The key length for HMAC-SHA are 20 bytes*/
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"));
        keySet.setClientWriteIv(new byte[8]);           // RC4 is not a block cipher so we don't need an iv
        keySet.setServerWriteIv(new byte[8]);           // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]);         // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]);   // ServerSide is not used

        RecordStreamCipher cipher = new RecordStreamCipher(context,
                keySet);

        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        /* sequence numbers are 64-bits long */
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolVersion(ProtocolVersion.SSL3.getValue());
        record.setCleanProtocolMessageBytes(data);

        /* the cipher is computed over the plaintext(data) and the mac
         * the mac is computed over the AuthenticatedMetaData + plaintext + LocalConnectionEndType*/
        cipher.encrypt(record);

        /* tests the meta data of the record
        the MAC is computed
   from the MAC secret, the sequence number, the message length, the
   message contents, and two fixed-character strings.  The message type
   field is necessary to ensure that messages intended for one SSL
   record layer client are not redirected to another.  The sequence
   number ensures that attempts to delete or reorder messages will be
   detected.  Since sequence numbers are 64 bits long, they should never
   overflow.  Messages from one party cannot be inserted into the
   other's output, since they use independent MAC secrets.  Similarly,
   the server-write and client-write keys are independent so stream
   cipher keys are used only once.
         * the MAC is computed from the MAC secret,
         * the sequence number,                  00 00 00 00 00 00 00 00 ---+
         * the type field,                                            16 ---+
         * the protocol version,                                   00 10 ---+---> authenticated meta data ---+
         * the message length,                                                                               |
         * the message contents,                          01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 ---+---> HMAC ---> hash
         * and two fixed character strings                                                  opad and ipad ---+
         *  .*/
        System.out.println(record.getComputations().getAuthenticatedMetaData());
        System.out.println(record.getComputations().getAuthenticatedNonMetaData());
        System.out.println(record.getCleanProtocolMessageBytes());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000160010"), record.getComputations()
                .getAuthenticatedMetaData().getValue());

        /* tests the encryption key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEF"),
                record.getComputations().getCipherKey().getValue());

        /* tests the mac key */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD"),
                record.getComputations().getMacKey().getValue());

        /* tests the mac only*/
        assertArrayEquals(ArrayConverter.hexStringToByteArray("740b1374aac883ec9171730684b9f7bf84c56cc1"), record
                .getComputations().getMac().getValue());

        /* tests the given plaintext + mac of the plaintext */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("010101010101010101010101010101017e9f01ddf2c70841a74f087e82bfe2e90e8d12ec"),
                record.getComputations().getPlainRecordBytes().getValue());

        /* tests the encryption */
        assertArrayEquals(ArrayConverter
                        .hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef71bd2a4c4e785acf6aeecfbce2111d3174b1e37f0"),
                record.getComputations().getCiphertext().getValue());

        /* tests protocol message bytes encrypted */
        assertArrayEquals(ArrayConverter.hexStringToByteArray("805264444f48ea5b98a0ceb3884c2ef71bd2a4c4e785acf6aeecfbce2111d3174b1e37f0"),
                record.getProtocolMessageBytes().getValue());
    }
}