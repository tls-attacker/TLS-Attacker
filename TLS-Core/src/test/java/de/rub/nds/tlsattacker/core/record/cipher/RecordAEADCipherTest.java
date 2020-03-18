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
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
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
import org.bouncycastle.util.test.TestRandomData;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
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
        keySet.setClientWriteKey(ArrayConverter
                .hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(new byte[0]);
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        // IV is not from keyblock
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

        // These fields are not used within blockciphers
        assertNull(record.getComputations().getCbcInitialisationVector());
        assertNull(record.getComputations().getMacKey());
        assertNull(record.getComputations().getMac());
        assertNull(record.getComputations().getMacValid());
        assertNull(record.getComputations().getPaddingValid());
        assertNull(record.getComputations().getPadding());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000"), record.getComputations()
                .getExplicitNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"), record.getComputations()
                .getAeadSalt().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"), record
                .getComputations().getGcmNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"), record
                .getComputations().getAuthenticationTag().getValue());
        assertTrue(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"), record.getComputations()
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0"),
                record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptGcmServer() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter
                .hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(new byte[0]);
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        // IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[12]); // ServerSide is not used
        keySet.setServerWriteKey(new byte[16]); // ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[0]); // ServerSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("FFEEDDCC"))); // ExplicitIV
        byte[] data = ArrayConverter
                .hexStringToByteArray("000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0");
        cipher = new RecordAEADCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);

        // These fields are not used within blockciphers
        assertNull(record.getComputations().getCbcInitialisationVector());
        assertNull(record.getComputations().getMacKey());
        assertNull(record.getComputations().getMac());
        assertNull(record.getComputations().getMacValid());
        assertNull(record.getComputations().getPaddingValid());
        assertNull(record.getComputations().getPadding());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000"), record.getComputations()
                .getExplicitNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"), record.getComputations()
                .getAeadSalt().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"), record
                .getComputations().getGcmNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"), record
                .getComputations().getAuthenticationTag().getValue());
        assertTrue(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"), record.getComputations()
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getCleanProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptGcmClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet.setServerWriteKey(ArrayConverter
                .hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(new byte[0]);
        keySet.setServerWriteIv(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        // IV is not from keyblock
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

        // These fields are not used within blockciphers
        assertNull(record.getComputations().getCbcInitialisationVector());
        assertNull(record.getComputations().getMacKey());
        assertNull(record.getComputations().getMac());
        assertNull(record.getComputations().getMacValid());
        assertNull(record.getComputations().getPaddingValid());
        assertNull(record.getComputations().getPadding());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000"), record.getComputations()
                .getExplicitNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"), record.getComputations()
                .getAeadSalt().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"), record
                .getComputations().getGcmNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"), record
                .getComputations().getAuthenticationTag().getValue());
        assertTrue(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"), record.getComputations()
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0"),
                record.getProtocolMessageBytes().getValue());
    }

    @Test
    public void testDecryptGcmClient() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet.setServerWriteKey(ArrayConverter
                .hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setServerWriteMacSecret(new byte[0]);
        keySet.setServerWriteIv(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        // IV is not from KeyBlock
        keySet.setClientWriteIv(new byte[12]); // ClientSide is not used
        keySet.setClientWriteKey(new byte[16]); // ClientSide is not used
        keySet.setClientWriteMacSecret(new byte[0]); // ClientSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("FFEEDDCC"))); // ExplicitIV
        byte[] data = ArrayConverter
                .hexStringToByteArray("000000000000000077D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216DEA10FBB5AF87DF49E75EA206892A1A0");
        cipher = new RecordAEADCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);

        // These fields are not used within blockciphers
        assertNull(record.getComputations().getCbcInitialisationVector());
        assertNull(record.getComputations().getMacKey());
        assertNull(record.getComputations().getMac());
        assertNull(record.getComputations().getMacValid());
        assertNull(record.getComputations().getPaddingValid());
        assertNull(record.getComputations().getPadding());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0000000000000000"), record.getComputations()
                .getExplicitNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"), record.getComputations()
                .getAeadSalt().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11223344556677889900AABB0000000000000000"), record
                .getComputations().getGcmNonce().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("DEA10FBB5AF87DF49E75EA206892A1A0"), record
                .getComputations().getAuthenticationTag().getValue());
        assertTrue(record.getComputations().getAuthenticationTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"), record.getComputations()
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("77D85417660273BBA5F220778CC117ECB7AAC7F46B0E07A8679215363031E912DA4494F0E8BEA216"),
                record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getCleanProtocolMessageBytes().getValue());
    }

    /**
     * Test of the encrypt method, of class RecordAEADCipher.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testEncrypt() throws NoSuchAlgorithmException, CryptoException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13_DRAFT21);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("4B63051EABCD514D7CB6D1899F472B9F56856B01BDBC5B733FBB47269E7EBDC2"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("ACC9DB33EE0968FAE7E06DAA34D642B146092CE7F9C9CF47670C66A0A6CE1C8C"));

        context.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        context.setConnection(new InboundConnection());
        this.cipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        byte[] plaintext = ArrayConverter.hexStringToByteArray("080000020000");
        Record record = new Record();
        record.setCleanProtocolMessageBytes(plaintext);
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.encrypt(record);
        byte[] ciphertext = record.getProtocolMessageBytes().getValue();
        byte[] ciphertext_correct = ArrayConverter
                .hexStringToByteArray("1BB3293A919E0D66F145AE830488E8D89BE5EC16688229");
        assertArrayEquals(ciphertext, ciphertext_correct);
    }

    /**
     * Test of the decrypt method, of class RecordAEADCipher.
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

        context.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        context.setConnection(new OutboundConnection());
        this.cipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        byte[] ciphertext = ArrayConverter.hexStringToByteArray("1BB3293A919E0D66F145AE830488E8D89BE5EC16688229");
        Record record = new Record();
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(ciphertext);
        record.setLength(record.getProtocolMessageBytes().getValue().length);
        record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);
        byte[] plaintext = record.getCleanProtocolMessageBytes().getValue();
        byte[] plaintext_correct = ArrayConverter.hexStringToByteArray("080000020000");
        assertArrayEquals(plaintext, plaintext_correct);
        assertEquals(ProtocolMessageType.HANDSHAKE.getValue(), (byte) record.getContentType().getValue());
    }

    @Test
    public void testInit() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13_DRAFT21);
        context.setHandshakeSecret(ArrayConverter
                .hexStringToByteArray("B2ED61DCDF8DD56D444A37827CF16C0C7D3AF4F95ACE1520746634F8EFED58E2"));
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("0DEE9BF2778DEE8AB18379C94B05C96F1ED1C28B3C51744180E2D47F97E46101"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("12756B2CA0395F1A1C3E268EF8610FBBAC8773E22F43BDABA385CE7E780A08B5"));

        context.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        this.cipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        assertArrayEquals(ArrayConverter.hexStringToByteArray("B8FF433DBB565709C9A6703B"), cipher.getKeySet()
                .getClientWriteIv());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("549EC618891BCA1E676D9A60"), cipher.getKeySet()
                .getServerWriteIv());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("B176715B3DD8D62B26E9FB4F19FDDAF8"), cipher.getKeySet()
                .getClientWriteKey());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("7DD498D9EA924142CD3BF45CD8A1B4B9"), cipher.getKeySet()
                .getServerWriteKey());
        assertArrayEquals(new byte[0], cipher.getKeySet().getClientWriteMacSecret());
        assertArrayEquals(new byte[0], cipher.getKeySet().getServerWriteMacSecret());
    }
}
