/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.BadFixedRandom;
import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class RecordBlockCipherTest {

    private TlsContext context;
    private RecordBlockCipher cipher;

    public RecordBlockCipherTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
    }

    @Test
    public void testConstructors() throws NoSuchAlgorithmException, CryptoException {
        // This test just checks that the init() method will not break
        List<AliasedConnection> mixedConnections = new ArrayList<>();
        mixedConnections.add(new InboundConnection());
        mixedConnections.add(new OutboundConnection());
        context.setClientRandom(new byte[]{0});
        context.setServerRandom(new byte[]{0});
        context.setMasterSecret(new byte[]{0});
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (!suite.isSCSV() && AlgorithmResolver.getCipherType(suite) == CipherType.BLOCK) {
                context.setSelectedCipherSuite(suite);
                for (AliasedConnection con : mixedConnections) {
                    context.setConnection(con);
                    for (ProtocolVersion version : ProtocolVersion.values()) {
                        if (version == ProtocolVersion.SSL2 || version.isTLS13()) {
                            continue;
                        }
                        if (!suite.isSupportedInProtocol(version)) {
                            continue;
                        }
                        context.setSelectedProtocolVersion(version);
                        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
                    }
                }
            }
        }
    }

    @SuppressWarnings("unused")
    @Test
    public void test() throws NoSuchAlgorithmException, CryptoException {
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setClientRandom(new byte[]{0});
        context.setServerRandom(new byte[]{0});
        context.setMasterSecret(new byte[]{0});
        context.setConnection(new OutboundConnection());
        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
    }

    /**
     * Test of calculateMac method, of class RecordBlockCipher.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testCalculateMac() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("03c08c3460b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("78f0c84e04d3c23cad94aad61ccae23ce79bcd9d2d6953f8ccbe0e528c63a238"));
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("F81015161244782B3541E6020140556E4FFEA98C57FCF6CEC172CD8B577DC73CCDE4B724E07DB8687DDF327CD8A68891"));
        byte[] data = ArrayConverter.hexStringToByteArray("000000000000000016030100101400000CCE92FBEC9131F48A63FED31F");

        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        Record record = new Record();
        record.setCleanProtocolMessageBytes(data);
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(BigInteger.ZERO);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.encrypt(record);

        byte[] mac = record.getComputations().getMac().getValue();
        byte[] correctMac = ArrayConverter.hexStringToByteArray("71573F726479AA9108FB86A4FA16BC1D5CB57530");
        assertArrayEquals(mac, correctMac);

    }

    /**
     * Test of encrypt method, of class RecordBlockCipher, for TLS10.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testEncryptTls10Client() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("03c08c3460b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("78f0c84e04d3c23cad94aad61ccae23ce79bcd9d2d6953f8ccbe0e528c63a238"));
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("F81015161244782B3541E6020140556E4FFEA98C57FCF6CEC172CD8B577DC73CCDE4B724E07DB8687DDF327CD8A68891"));
        byte[] data = ArrayConverter
                .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setServerWriteIv(new byte[8]); //ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); //ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); //ServerSide is not used
        
        cipher = new RecordBlockCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.encrypt(record);

        // These fields are not used within blockciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getImplicitNonce());
        assertNull(record.getComputations().getNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010028"), record.getComputations()
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"), record.getComputations()
                .getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"), record
                .getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("7952A83507720317BEE172747A2A6C84759E6A33"), record
                .getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"), record.getComputations().getPadding()
                .getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303037952A83507720317BEE172747A2A6C84759E6A3303030303"),
                record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
                record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
                record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls10Client() throws NoSuchAlgorithmException, CryptoException {
        // This is effectivly the testEncryptTls10() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        byte[] data = ArrayConverter
                .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD");
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"));
        keySet.setServerWriteIv(new byte[8]); //ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); //ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); //ServerSide is not used

        cipher = new RecordBlockCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.decrypt(record);

        // These fields are not used within blockciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getImplicitNonce());
        assertNull(record.getComputations().getNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603010028"), record.getComputations()
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"), record.getComputations()
                .getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"), record
                .getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("7952A83507720317BEE172747A2A6C84759E6A33"), record
                .getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"), record.getComputations().getPadding()
                .getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB57530030303037952A83507720317BEE172747A2A6C84759E6A3303030303"),
                record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
                record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD"),
                record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testEncryptTls12Client() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[8]); //IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[8]); //ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); //ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); //ServerSide is not used
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"))); //IV
        byte[] data = ArrayConverter
                .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        cipher = new RecordBlockCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.encrypt(record);

        // These fields are not used within blockciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getImplicitNonce());
        assertNull(record.getComputations().getNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getTagValid());

        
        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"), record.getComputations()
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(data, record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"), record.getComputations()
                .getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"), record
                .getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("86878C26AA74D2576F5849AEF6CFED88BFD7FE7E"), record
                .getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"), record.getComputations().getPadding()
                .getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB575300303030386878C26AA74D2576F5849AEF6CFED88BFD7FE7E03030303"),
                record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
                record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
                record.getProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }

    @Test
    public void testDecryptTls12Client() throws NoSuchAlgorithmException, CryptoException {
        // This is effectivly the testEncryptTls12() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        keySet.setClientWriteMacSecret(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"));
        keySet.setClientWriteIv(new byte[8]); //IV is not from KeyBlock
        keySet.setServerWriteIv(new byte[8]); //ServerSide is not used
        keySet.setServerWriteKey(new byte[24]); //ServerSide is not used
        keySet.setServerWriteMacSecret(new byte[20]); //ServerSide is not used
        
        byte[] data = ArrayConverter
                .hexStringToByteArray("1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE");
        cipher = new RecordBlockCipher(context, keySet);
        Record record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);
        
        
        System.out.println(ArrayConverter.bytesToHexString(record.getComputations().getCiphertext().getValue()));
        
        // These fields are not used within blockciphers
        assertNull(record.getComputations().getExplicitNonce());
        assertNull(record.getComputations().getImplicitNonce());
        assertNull(record.getComputations().getNonce());
        assertNull(record.getComputations().getAuthenticationTag());
        assertNull(record.getComputations().getTagValid());

        assertArrayEquals(ArrayConverter.hexStringToByteArray("00000000000000001603030028"), record.getComputations()
                .getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1ACF314DA7208EB8"), record.getComputations()
                .getCbcInitialisationVector().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("183612323C5507EDAA5BF0DE71272A2EA87B1165"), record
                .getComputations().getMacKey().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("86878C26AA74D2576F5849AEF6CFED88BFD7FE7E"), record
                .getComputations().getMac().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("03030303"), record.getComputations().getPadding()
                .getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB575300303030386878C26AA74D2576F5849AEF6CFED88BFD7FE7E03030303"),
                record.getComputations().getPlainRecordBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
                record.getComputations().getCiphertext().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1ACF314DA7208EB8C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23658D0028D806AD6DCFB4A1C95523EE32182FE110528D80AE"),
                record.getProtocolMessageBytes().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"),
                record.getCleanProtocolMessageBytes().getValue());

        assertTrue(record.getComputations().getMacValid());
        assertTrue(record.getComputations().getPaddingValid());
    }
}
