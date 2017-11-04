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
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class StaticTicketCryptoTest {
    private static final Logger LOGGER = LogManager.getLogger(StaticTicketCryptoTest.class);

    public StaticTicketCryptoTest() {
    }

    /**
     * Test of encryptAES_128_CBC method, of class StaticTicketCrypto. Assuming
     * that the key, iv and data has the correct length. Testvector from
     * https://tools.ietf.org/html/rfc3602#section-4
     */
    @Test
    public void testEncryptAES_128_CBC() {
        /*-
        PKCS7 is not used in the RFC testvectors
        TODO: Find some useable testvectors
        
        LOGGER.info("Encrypting AES128 CBC");
        byte[] plaintext = ArrayConverter
                .hexStringToByteArray("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
        byte[] key = ArrayConverter.hexStringToByteArray("56e47a38c5598974bc46903dba290349");
        byte[] iv = ArrayConverter.hexStringToByteArray("8ce82eefbea0da3c44699ed7db51b7d9");
        byte[] expResult = ArrayConverter
                .hexStringToByteArray("c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55");
        byte[] result = StaticTicketCrypto.encryptAES_128_CBC(plaintext, key, iv);
        assertArrayEquals(expResult, result);
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
        
        LOGGER.info("Decrypting AES128 CBC");
        byte[] ciphertext = ArrayConverter
                .hexStringToByteArray("c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55");
        byte[] key = ArrayConverter.hexStringToByteArray("56e47a38c5598974bc46903dba290349");
        byte[] iv = ArrayConverter.hexStringToByteArray("8ce82eefbea0da3c44699ed7db51b7d9");
        byte[] expResult = ArrayConverter
                .hexStringToByteArray("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
        byte[] result = StaticTicketCrypto.decryptAES_128_CBC(ciphertext, key, iv);
        assertArrayEquals(expResult, result);
        -*/
    }

    /**
     * Test of random, wrong and used data.
     */
    @Test
    public void testEncDecAES_128_CBC() {
        LOGGER.info("EncDec AES128 CBC with random 16 byte key/iv and 120 byte message.");
        byte[] plaintext = new byte[120];
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        RandomHelper.getRandom().nextBytes(plaintext);
        RandomHelper.getRandom().nextBytes(key);
        RandomHelper.getRandom().nextBytes(iv);
        byte[] resultenc = StaticTicketCrypto.encryptAES_128_CBC(plaintext, key, iv);
        byte[] resultdec = StaticTicketCrypto.decryptAES_128_CBC(resultenc, key, iv);
        assertFalse(resultdec.length == 0);
        assertArrayEquals(plaintext, resultdec);

        LOGGER.info("Check result for wrong data input.");
        resultenc = new byte[160];
        RandomHelper.getRandom().nextBytes(resultenc);
        resultdec = StaticTicketCrypto.decryptAES_128_CBC(resultenc, key, iv);
        assertFalse(Arrays.equals(plaintext, resultdec));

        LOGGER.info("EncDec AES128 CBC with used 16byte key and random 120 byte message.");
        key = ArrayConverter.hexStringToByteArray("536563757265535469636b65744b6579");
        resultenc = StaticTicketCrypto.encryptAES_128_CBC(plaintext, key, iv);
        resultdec = StaticTicketCrypto.decryptAES_128_CBC(resultenc, key, iv);
        assertFalse(resultdec.length == 0);
        assertArrayEquals(plaintext, resultdec);
    }

    /**
     * Test of generateHMAC_SHA256 method, of class StaticTicketCrypto. Assuming
     * that the key has the correct length. Testvector from
     * https://tools.ietf.org/html/rfc4231#section-4.2
     */
    @Test
    public void testGenerateHMAC_SHA256() {
        LOGGER.info("Generate HMAC SHA256");
        byte[] plaintext = ArrayConverter.hexStringToByteArray("4869205468657265");
        byte[] key = ArrayConverter.hexStringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] expResult = ArrayConverter
                .hexStringToByteArray("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        byte[] result = StaticTicketCrypto.generateHMAC_SHA256(plaintext, key);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of verifyHMAC_SHA256 method, of class StaticTicketCrypto. Assuming
     * that the key has the correct length. Testvector from
     * https://tools.ietf.org/html/rfc4231#section-4.2
     */
    @Test
    public void testVerifyHMAC_SHA256() {
        LOGGER.info("Verify HMAC SHA256");
        byte[] mac = ArrayConverter
                .hexStringToByteArray("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        byte[] plaintext = ArrayConverter.hexStringToByteArray("4869205468657265");
        byte[] key = ArrayConverter.hexStringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        boolean expResult = true;
        boolean result = StaticTicketCrypto.verifyHMAC_SHA256(mac, plaintext, key);
        assertEquals(expResult, result);
    }

    /**
     * Test of random, wrong and used data.
     */
    @Test
    public void testGenVrfyHMAC_SHA256() {
        LOGGER.info("GenVrfy HMAC SHA256 with random 20 byte key and 120 byte message.");
        byte[] plaintext = new byte[120];
        byte[] key = new byte[20];
        RandomHelper.getRandom().nextBytes(plaintext);
        RandomHelper.getRandom().nextBytes(key);
        byte[] resultmac = StaticTicketCrypto.generateHMAC_SHA256(plaintext, key);
        boolean result = StaticTicketCrypto.verifyHMAC_SHA256(resultmac, plaintext, key);
        assertTrue(result);

        LOGGER.info("Check result for wrong data input.");
        RandomHelper.getRandom().nextBytes(resultmac);
        result = StaticTicketCrypto.verifyHMAC_SHA256(resultmac, plaintext, key);
        assertFalse(result);

        LOGGER.info("GenVrfy HMAC SHA256 with used 32byte key and random 120 byte message.");
        key = ArrayConverter.hexStringToByteArray("536563757265535469636b65744b6579536563757265535469636b65744b6579");
        resultmac = StaticTicketCrypto.generateHMAC_SHA256(plaintext, key);
        result = StaticTicketCrypto.verifyHMAC_SHA256(resultmac, plaintext, key);
        assertTrue(result);
    }
}
