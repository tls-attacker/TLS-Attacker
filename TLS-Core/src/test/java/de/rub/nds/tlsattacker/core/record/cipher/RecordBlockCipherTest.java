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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
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
        context.setClientRandom(new byte[] { 0 });
        context.setServerRandom(new byte[] { 0 });
        context.setMasterSecret(new byte[] { 0 });
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (!suite.isSCSV() && AlgorithmResolver.getCipherType(suite) == CipherType.BLOCK
                    && !suite.name().contains("FORTEZZA")) {
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
        // test FORTEZZA for SSLv3 ... Fortezza unterstützen wir "noch" garnicht
        // for (CipherSuite suite : CipherSuite.values()) {
        // if (!suite.equals(CipherSuite.TLS_UNKNOWN_CIPHER) && !suite.isSCSV()
        // && suite.name().contains("FORTEZZA")
        // && AlgorithmResolver.getCipherType(suite) == CipherType.BLOCK) {
        // context.setSelectedCipherSuite(suite);
        // context.setConnectionEnd(new GeneralConnectionEnd());
        // context.setSelectedProtocolVersion(ProtocolVersion.SSL3);
        // for (ConnectionEndType end : ConnectionEndType.values()) {
        // ((GeneralConnectionEnd)
        // context.getConnectionEnd()).setConnectionEndType(end);
        // RecordBlockCipher cipher = new RecordBlockCipher(context);
        // }
        // }
        // }
    }

    @SuppressWarnings("unused")
    @Test
    public void test() throws NoSuchAlgorithmException, CryptoException {
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setClientRandom(new byte[] { 0 });
        context.setServerRandom(new byte[] { 0 });
        context.setMasterSecret(new byte[] { 0 });
        context.setConnection(new OutboundConnection());
        RecordBlockCipher cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
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
        byte[] mac = cipher.calculateMac(data, context.getChooser().getConnectionEndType());
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

        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        byte[] ciphertext = cipher.encrypt(new EncryptionRequest(data, cipher.getEncryptionIV(), null))
                .getCompleteEncryptedCipherText();
        byte[] correctCiphertext = ArrayConverter
                .hexStringToByteArray("C34B06D54CDE2A5AF25EE0AE1896F6F149720FA9EC205C6629B2C7F52A7F3A72931E351D4AD26E23");
        assertArrayEquals(correctCiphertext, ciphertext);
        data = ArrayConverter.hexStringToByteArray("54657374EDE63C0E2BDAB2875D35FFC30ED4C327F7B54CCB0707070707070707");
        ciphertext = cipher.encrypt(new EncryptionRequest(data, cipher.getEncryptionIV(), null))
                .getCompleteEncryptedCipherText();
        correctCiphertext = ArrayConverter
                .hexStringToByteArray("7829006A6B93FA6348E1074E58CCEFA9EBBEA3202ABA82F9A2B7BC26D187AF08");
        assertArrayEquals(correctCiphertext, ciphertext);
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
        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        EncryptionResult encryptionResult = cipher.encrypt(new EncryptionRequest(data, iv, null));

        byte[] correctCiphertext = ArrayConverter
                .hexStringToByteArray("60B420BB3851D9D47ACB933DBE70399BB7556D6BBB782F6B13EF212326DEE109ED896514DD83AB9DDB7C9B8ACB79E738E0A928C05217E90DC98D6F3E326C2751A0B12C06E2C3D852E72075098F3387E1");
        assertArrayEquals(correctCiphertext, encryptionResult.getCompleteEncryptedCipherText());
        assertArrayEquals(iv, encryptionResult.getInitialisationVector());

        data = ArrayConverter.hexStringToByteArray("54657374EDE63C0E2BDAB2875D35FFC30ED4C327F7B54CCB0707070707070707");
        correctCiphertext = ArrayConverter
                .hexStringToByteArray("60B420BB3851D9D47ACB933DBE70399BE55651CF88774ED9990F91F4BD25C30881331F16DC8FBD609F0E7714CD4678EF");
        encryptionResult = cipher.encrypt(new EncryptionRequest(data, iv, null));
        assertArrayEquals(correctCiphertext, encryptionResult.getCompleteEncryptedCipherText());
        assertArrayEquals(iv, encryptionResult.getInitialisationVector());
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
        byte[] data = ArrayConverter
                .hexStringToByteArray("BCD644DF7E82BF0097E1B0C16CDD53199733EE70629FA82DAC7B0B4F6100B602ACBA3B8EA6A7741B");

        cipher = new RecordBlockCipher(context, KeySetGenerator.generateKeySet(context));
        byte[] plaintext = cipher.decrypt(new DecryptionRequest(null, data)).getDecryptedCipherText();
        byte[] correctPlaintext = ArrayConverter
                .hexStringToByteArray("1400000CC84350158844FE559EC327B77F44B9791ECB11453B7FC40ED27C35DDDC7C250603030303");
        assertArrayEquals(plaintext, correctPlaintext);
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
        byte[] plaintext = cipher.decrypt(new DecryptionRequest(null, data)).getDecryptedCipherText();
        byte[] correctPlaintext = ArrayConverter
                .hexStringToByteArray("7F1F9E3AA2EAD435ED42143C54D81FEDAC85A400AF369CABFA1B77EBB3647B534FB8447306D14FE610F897EBE455A43ED47140370DB20BF3181067641D20E425");
        assertArrayEquals(plaintext, correctPlaintext);
    }

    /**
     * Test of getMacLength method, of class RecordBlockCipher.
     */
    @Test
    public void testGetMacLength() {
    }

    /**
     * Test of calculatePadding method, of class RecordBlockCipher.
     */
    @Test
    public void testCalculatePadding() {
    }

    /**
     * Test of getPaddingLength method, of class RecordBlockCipher.
     */
    @Test
    public void testGetPaddingLength() {
    }

}
