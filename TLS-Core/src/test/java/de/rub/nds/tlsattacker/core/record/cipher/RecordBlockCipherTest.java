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
    public void testEncryptTls10() throws NoSuchAlgorithmException, CryptoException {
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
        // IV : 1ACF314DA7208EB8
        // ClientWriteKey: 65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC
        // ClientWriteMACKey: 183612323C5507EDAA5BF0DE71272A2EA87B1165
        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
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
    public void testDecryptTls10() throws NoSuchAlgorithmException, CryptoException {
        //This is effectivly the testEncryptTls10() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("03c08c3460b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("78f0c84e04d3c23cad94aad61ccae23ce79bcd9d2d6953f8ccbe0e528c63a238"));
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("F81015161244782B3541E6020140556E4FFEA98C57FCF6CEC172CD8B577DC73CCDE4B724E07DB8687DDF327CD8A68891"));
        byte[] data = ArrayConverter
                .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD");
        // IV : 1ACF314DA7208EB8
        // ClientWriteKey: 65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC
        // ClientWriteMACKey: 183612323C5507EDAA5BF0DE71272A2EA87B1165
        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
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
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"), record.getComputations().getAuthenticatedNonMetaData().getValue());
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
    public void testEncryptTls12() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("03c08c3460b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("78f0c84e04d3c23cad94aad61ccae23ce79bcd9d2d6953f8ccbe0e528c63a238"));
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("F81015161244782B3541E6020140556E4FFEA98C57FCF6CEC172CD8B577DC73CCDE4B724E07DB8687DDF327CD8A68891"));
        byte[] data = ArrayConverter
                .hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303");
        // IV : 1ACF314DA7208EB8
        // ClientWriteKey: 65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC
        // ClientWriteMACKey: 183612323C5507EDAA5BF0DE71272A2EA87B1165
        context.getConfig().getDefault
        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
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
    public void testDecryptTls12() throws NoSuchAlgorithmException, CryptoException {
        //This is effectivly the testEncryptTls10() test in reverse
        context.setConnection(new InboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("03c08c3460b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("78f0c84e04d3c23cad94aad61ccae23ce79bcd9d2d6953f8ccbe0e528c63a238"));
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("F81015161244782B3541E6020140556E4FFEA98C57FCF6CEC172CD8B577DC73CCDE4B724E07DB8687DDF327CD8A68891"));
        byte[] data = ArrayConverter
                .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E231DE35AD06AC17B8A26638290BB5846283B4788D8C42119BD");
        // IV : 1ACF314DA7208EB8
        // ClientWriteKey: 65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC
        // ClientWriteMACKey: 183612323C5507EDAA5BF0DE71272A2EA87B1165
        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
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
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1400000CCE92FBEC9131F48A63FED31F71573F726479AA9108FB86A4FA16BC1D5CB5753003030303"), record.getComputations().getAuthenticatedNonMetaData().getValue());
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

    /**
     * Test of encrypt method, of class RecordBlockCipher, for TLS12.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testEncryptTls12() throws NoSuchAlgorithmException, CryptoException {
        RandomHelper.setRandom(new BadRandom(new Random(0), null));
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("04324f7660b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("60e4c0b6e3c608e9009b9ea6f3b363b2ffba6c68aae03e238906e1d39fc28ff2"));
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("E2C53BF814820DBBDEE155136C3D1266366E15DF235C8409CEBA95F66B7F3471D093308CA889162888B1B2AF59C12E66"));
        byte[] iv = ArrayConverter.hexStringToByteArray("60B420BB3851D9D47ACB933DBE70399B");
        byte[] data = ArrayConverter
                .hexStringToByteArray("1400000C085BE7DCDCC455020E3B578A9812C4AAD8FDCA97E7B389632B6DD1F3D61A3878413B995C942EA842CE8B2E4B0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F");
        Record record = new Record();
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setCleanProtocolMessageBytes(data);
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());

        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        cipher.encrypt(record);

        byte[] correctCiphertext = ArrayConverter
                .hexStringToByteArray("60B420BB3851D9D47ACB933DBE70399BB7556D6BBB782F6B13EF212326DEE109ED896514DD83AB9DDB7C9B8ACB79E738E0A928C05217E90DC98D6F3E326C2751A0B12C06E2C3D852E72075098F3387E1");
        assertArrayEquals(correctCiphertext, record.getProtocolMessageBytes().getValue());
        assertArrayEquals(iv, record.getComputations().getCbcInitialisationVector().getValue());

        data = ArrayConverter.hexStringToByteArray("54657374EDE63C0E2BDAB2875D35FFC30ED4C327F7B54CCB0707070707070707");
        correctCiphertext = ArrayConverter
                .hexStringToByteArray("60B420BB3851D9D47ACB933DBE70399BE55651CF88774ED9990F91F4BD25C30881331F16DC8FBD609F0E7714CD4678EF");
        record = new Record();
        record.setCleanProtocolMessageBytes(data);
        cipher.encrypt(record);
        assertArrayEquals(correctCiphertext, record.getProtocolMessageBytes().getValue());
        assertArrayEquals(iv, record.getComputations().getCbcInitialisationVector().getValue());
    }

    /**
     * Test of decrypt method, of class RecordBlockCipher, for TLS10.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testDecrypt10() throws NoSuchAlgorithmException, CryptoException {
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("03c08c3460b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("78f0c84e04d3c23cad94aad61ccae23ce79bcd9d2d6953f8ccbe0e528c63a238"));
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("F81015161244782B3541E6020140556E4FFEA98C57FCF6CEC172CD8B577DC73CCDE4B724E07DB8687DDF327CD8A68891"));
        byte[] ciphertext = ArrayConverter
                .hexStringToByteArray("BCD644DF7E82BF0097E1B0C16CDD53199733EE70629FA82DAC7B0B4F6100B602ACBA3B8EA6A7741B");

        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        Record record = new Record();
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.setProtocolMessageBytes(ciphertext);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        cipher.decrypt(record);
        byte[] correctPlaintext = ArrayConverter
                .hexStringToByteArray("1400000CC84350158844FE559EC327B77F44B9791ECB11453B7FC40ED27C35DDDC7C250603030303");
        assertArrayEquals(correctPlaintext, record.getCleanProtocolMessageBytes().getValue());
    }

    /**
     * Test of decrypt method, of class RecordBlockCipher, for TLS12.
     *
     * @throws java.security.NoSuchAlgorithmException
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testDecrypt12() throws NoSuchAlgorithmException, CryptoException {
        RandomHelper.setRandom(new BadRandom(new Random(0), null));
        context.setConnection(new OutboundConnection());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("03c08c3460b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("78f0c84e04d3c23cad94aad61ccae23ce79bcd9d2d6953f8ccbe0e528c63a238"));
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("F81015161244782B3541E6020140556E4FFEA98C57FCF6CEC172CD8B577DC73CCDE4B724E07DB8687DDF327CD8A68891"));
        byte[] data = ArrayConverter
                .hexStringToByteArray("45DCB1853201C59037AFF4DFE3F442B7CDB4DB1348894AE76E251F4491A6F5F859B2DE12879C6D86D4BDC83CAB854E33EF5CC51B25942E64EC6730AB1DDB5806E900B7B0C32D9BFF59C0F01334C0F673");

        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        Record record = new Record();
        record.prepareComputations();
        record.setSequenceNumber(new BigInteger("0"));
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.setProtocolMessageBytes(data);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        cipher.decrypt(record);
        byte[] correctPlaintext = ArrayConverter
                .hexStringToByteArray("7F1F9E3AA2EAD435ED42143C54D81FEDAC85A400AF369CABFA1B77EBB3647B534FB8447306D14FE610F897EBE455A43ED47140370DB20BF3181067641D20E425");
        assertArrayEquals(correctPlaintext, record.getCleanProtocolMessageBytes().getValue());
    }
}
