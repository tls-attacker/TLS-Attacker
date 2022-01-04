/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StaticTicketCrypto {

    private static final Logger LOGGER = LogManager.getLogger();

    public static byte[] encrypt(CipherAlgorithm cipherAlgorithm, byte[] plaintextUnpadded, byte[] key, byte[] iv)
        throws CryptoException {
        byte[] result = new byte[0];
        try {
            byte[] plaintext = addPadding(plaintextUnpadded, cipherAlgorithm.getKeySize());
            Cipher cipher = Cipher.getInstance(cipherAlgorithm.getJavaName());
            BulkCipherAlgorithm bulkCipher = BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherAlgorithm);
            SecretKeySpec secretKey = new SecretKeySpec(key, bulkCipher.getJavaName());
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            result = cipher.doFinal(plaintext);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
            | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            throw new CryptoException("Error while StatePlaintext Encryption. See Debug-Log for more Information.", ex);
        }
        return result;
    }

    public static byte[] decrypt(CipherAlgorithm cipherAlgorithm, byte[] ciphertext, byte[] key, byte[] iv)
        throws CryptoException {
        byte[] result = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm.getJavaName());
            BulkCipherAlgorithm bulkCipher = BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherAlgorithm);
            SecretKeySpec secretKey = new SecretKeySpec(key, bulkCipher.getJavaName());
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            result = cipher.doFinal(ciphertext);
            result = removePadding(result);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
            | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            LOGGER.warn("Encountered exception while encrypting the StatePlaintext with " + cipherAlgorithm.name());
            LOGGER.debug(ex);
            throw new CryptoException("Error while StatePlaintext Decryption. See Debug-Log for more Information.");
        }
        return result;
    }

    public static byte[] generateHMAC(MacAlgorithm macAlgorithm, byte[] plaintext, byte[] key) throws CryptoException {
        byte[] result = new byte[0];
        try {
            Mac mac = Mac.getInstance(macAlgorithm.getJavaName());
            SecretKeySpec macKey = new SecretKeySpec(key, macAlgorithm.getJavaName());
            mac.init(macKey);
            result = mac.doFinal(plaintext);
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            LOGGER.warn(
                "Encountered exception while generating the HMAC " + macAlgorithm.name() + " of an encryptedState.");
            LOGGER.debug(ex);
            throw new CryptoException("Error while HMAC generation. See Debug-Log for more Information.");
        }
        return result;
    }

    public static boolean verifyHMAC(MacAlgorithm macAlgo, byte[] mac, byte[] plaintext, byte[] key)
        throws CryptoException {
        byte[] newMAC = generateHMAC(macAlgo, plaintext, key);
        boolean result = Arrays.equals(mac, newMAC);
        return result;
    }

    private static byte[] addPadding(byte[] plainTextRaw, int keySize) {
        byte padLen = (byte) (0xFF & (keySize - (plainTextRaw.length % keySize)));
        byte[] padding = new byte[padLen];
        for (int i = 0; i < padLen; i++) {
            padding[i] = padLen;
        }
        byte[] padded = ArrayConverter.concatenate(plainTextRaw, padding);
        return padded;
    }

    private static byte[] removePadding(byte[] result) {
        int padLen = result[result.length - 1];
        return Arrays.copyOf(result, result.length - padLen);
    }

    private StaticTicketCrypto() {
    }
}
