/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Test;

public class StaticTicketCryptoTest {

    private static final Logger LOGGER = LogManager.getLogger();

    public StaticTicketCryptoTest() {
    }

    /**
     * Test of encryptAES_128_CBC method, of class StaticTicketCrypto. Assuming
     * that the key, iv and data has the correct length.
     */
    @Test
    public void testEncryptAES_128_CBC() {
        /*-
        PKCS7 is not used in the RFC testvectors
        TODO: Find some useable testvectors
        -*/
    }

    /**
     * Test of decryptAES_128_CBC method, of class StaticTicketCrypto. Assuming
     * that the key, iv and data has the correct length. Testvector from
     * https://tools.ietf.org/html/rfc3602#section-4
     */
    @Test
    public void testDecryptAES_128_CBC() {
        /*-
        PKCS7 is not used in the RFC testvectors
        TODO: Find some useable testvectors
        -*/
    }

    /**
     * Test of random, wrong and used data.
     * 
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testEncDecAES_128_CBC() throws CryptoException {
        LOGGER.info("EncDec AES128 CBC with random 16 byte key/iv and 120 byte message.");
        byte[] plaintext = new byte[120];
        RandomHelper.getRandom().nextBytes(plaintext);

        byte[] key128 = new byte[16];
        byte[] iv128 = new byte[16];
        RandomHelper.getRandom().nextBytes(key128);
        RandomHelper.getRandom().nextBytes(iv128);

        byte[] resultenc = StaticTicketCrypto.encrypt(CipherAlgorithm.AES_128_CBC, plaintext, key128, iv128);
        byte[] resultdec = StaticTicketCrypto.decrypt(CipherAlgorithm.AES_128_CBC, resultenc, key128, iv128);
        assertFalse(resultdec.length == 0);
        assertArrayEquals(plaintext, resultdec);

        LOGGER.info("Check result for wrong data input.");
        resultenc = new byte[160];
        RandomHelper.getRandom().nextBytes(resultenc);
        resultdec = StaticTicketCrypto.decrypt(CipherAlgorithm.AES_128_CBC, resultenc, key128, iv128);
        assertFalse(Arrays.equals(plaintext, resultdec));

        LOGGER.info("EncDec AES128 CBC with used 16byte key128 and random 120 byte message.");
        key128 = ArrayConverter.hexStringToByteArray("536563757265535469636b65744b6579");
        resultenc = StaticTicketCrypto.encrypt(CipherAlgorithm.AES_128_CBC, plaintext, key128, iv128);
        resultdec = StaticTicketCrypto.decrypt(CipherAlgorithm.AES_128_CBC, resultenc, key128, iv128);
        assertFalse(resultdec.length == 0);
        assertArrayEquals(plaintext, resultdec);
    }

    /**
     * Test of generateHMAC_SHA256 method, of class StaticTicketCrypto. Assuming
     * that the key has the correct length. Testvector from
     * https://tools.ietf.org/html/rfc4231#section-4.2
     * 
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testGenerateHMAC_SHA256() throws CryptoException {
        LOGGER.info("Generate HMAC SHA256");
        byte[] plaintext = ArrayConverter.hexStringToByteArray("4869205468657265");
        byte[] key = ArrayConverter.hexStringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] expResult = ArrayConverter
                .hexStringToByteArray("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        byte[] result = StaticTicketCrypto.generateHMAC(MacAlgorithm.HMAC_SHA256, plaintext, key);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of verifyHMAC_SHA256 method, of class StaticTicketCrypto. Assuming
     * that the key has the correct length. Testvector from
     * https://tools.ietf.org/html/rfc4231#section-4.2
     * 
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testVerifyHMAC_SHA256() throws CryptoException {
        LOGGER.info("Verify HMAC SHA256");
        byte[] mac = ArrayConverter
                .hexStringToByteArray("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        byte[] plaintext = ArrayConverter.hexStringToByteArray("4869205468657265");
        byte[] key = ArrayConverter.hexStringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        boolean expResult = true;
        boolean result = StaticTicketCrypto.verifyHMAC(MacAlgorithm.HMAC_SHA256, mac, plaintext, key);
        assertEquals(expResult, result);
    }

    /**
     * Test of random, wrong and used data.
     * 
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testGenVrfyHMAC_SHA256() throws CryptoException {
        LOGGER.info("GenVrfy HMAC SHA256 with random 20 byte key and 120 byte message.");
        byte[] plaintext = new byte[120];
        byte[] key = new byte[20];
        RandomHelper.getRandom().nextBytes(plaintext);
        RandomHelper.getRandom().nextBytes(key);
        byte[] resultmac = StaticTicketCrypto.generateHMAC(MacAlgorithm.HMAC_SHA256, plaintext, key);
        boolean result = StaticTicketCrypto.verifyHMAC(MacAlgorithm.HMAC_SHA256, resultmac, plaintext, key);
        assertTrue(result);

        LOGGER.info("Check result for wrong data input.");
        RandomHelper.getRandom().nextBytes(resultmac);
        result = StaticTicketCrypto.verifyHMAC(MacAlgorithm.HMAC_SHA256, resultmac, plaintext, key);
        assertFalse(result);

        LOGGER.info("GenVrfy HMAC SHA256 with used 32byte key and random 120 byte message.");
        key = ArrayConverter.hexStringToByteArray("536563757265535469636b65744b6579536563757265535469636b65744b6579");
        resultmac = StaticTicketCrypto.generateHMAC(MacAlgorithm.HMAC_SHA256, plaintext, key);
        result = StaticTicketCrypto.verifyHMAC(MacAlgorithm.HMAC_SHA256, resultmac, plaintext, key);
        assertTrue(result);
    }
}
