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
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class RecordAEADCipherTest {

    private TlsContext context;
    private RecordAEADCipher cipher;

    public RecordAEADCipherTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
        this.context = new TlsContext();
    }

    @Test
    public void testEncryptGcmServer() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(new byte[0]);
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        // IV is not from key block
        keySet.setServerWriteIv(new byte[12]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[0]); // ServerSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("FFEEDDCC"))); // ExplicitIV
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        cipher = new RecordAEADCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getCbcInitialisationVector());
        assertNull(record.getComputations().getMacKey());
        assertNull(record.getComputations().getMac());
        assertNull(record.getComputations().getMacValid());
        assertNull(record.getComputations().getPaddingValid());
        assertNull(record.getComputations().getPadding());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000"),
            record.getComputations().getExplicitNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
            record.getComputations().getAeadSalt().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"),
            record.getComputations().getGcmNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"),
            record.getComputations().getAuthenticationTag().getValue());
        assertTrue(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptGcmServer() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(new byte[0]);
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        // IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[12]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[0]); // ServerSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("FFEEDDCC"))); // ExplicitIV
        byte[] data = ArrayConverter.hexStringToByteArray(
            "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0");
        cipher = new RecordAEADCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getCbcInitialisationVector());
        assertNull(record.getComputations().getMacKey());
        assertNull(record.getComputations().getMac());
        assertNull(record.getComputations().getMacValid());
        assertNull(record.getComputations().getPaddingValid());
        assertNull(record.getComputations().getPadding());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000"),
            record.getComputations().getExplicitNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
            record.getComputations().getAeadSalt().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"),
            record.getComputations().getGcmNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"),
            record.getComputations().getAuthenticationTag().getValue());
        assertTrue(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptGcmClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(new byte[0]);
        keySet.setServerWriteIv(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        // IV is not from key block
        keySet.setClientWriteIv(new byte[12]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[16]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[0]); // ClientSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("FFEEDDCC"))); // ExplicitIV
        byte[] data = ArrayConverter
            .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        cipher = new RecordAEADCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.encrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getCbcInitialisationVector());
        assertNull(record.getComputations().getMacKey());
        assertNull(record.getComputations().getMac());
        assertNull(record.getComputations().getMacValid());
        assertNull(record.getComputations().getPaddingValid());
        assertNull(record.getComputations().getPadding());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000"),
            record.getComputations().getExplicitNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
            record.getComputations().getAeadSalt().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"),
            record.getComputations().getGcmNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"),
            record.getComputations().getAuthenticationTag().getValue());
        assertTrue(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
            "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0"),
            record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptGcmClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet
            .setServerWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(new byte[0]);
        keySet.setServerWriteIv(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        // IV is not from KeyBlock
        keySet.setClientWriteIv(new byte[12]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[16]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[0]); // ClientSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("FFEEDDCC"))); // ExplicitIV
        byte[] data = ArrayConverter.hexStringToByteArray(
            "000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0");
        cipher = new RecordAEADCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);

        // These fields are not used within block ciphers
        assertNull(record.getComputations().getCbcInitialisationVector());
        assertNull(record.getComputations().getMacKey());
        assertNull(record.getComputations().getMac());
        assertNull(record.getComputations().getMacValid());
        assertNull(record.getComputations().getPaddingValid());
        assertNull(record.getComputations().getPadding());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000"),
            record.getComputations().getExplicitNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"),
            record.getComputations().getAeadSalt().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"),
            record.getComputations().getGcmNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"),
            record.getComputations().getAuthenticationTag().getValue());
        assertTrue(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"),
            record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
            record.getComputations().getAuthenticatedNonMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
            record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
            record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
            record.getCleanProtocolMessageBytes().getValue());
    }
}
