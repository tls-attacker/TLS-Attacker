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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
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

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class StaticTicketCrypto {

    private static final Logger LOGGER = LogManager.getLogger(StaticTicketCrypto.class);

    public static byte[] encrypt(CipherAlgorithm cipherAlgorithm, byte[] plaintextUnpadded, byte[] key, byte[] iv) {
        byte[] result = new byte[0];
        try {
            byte[] plaintext = addPadding(plaintextUnpadded, cipherAlgorithm.getKeySize());
            Cipher cipher = Cipher.getInstance(cipherAlgorithm.getJavaName());
            BulkCipherAlgorithm bulkcipher = BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherAlgorithm);
            SecretKeySpec secretkey = new SecretKeySpec(key, bulkcipher.getJavaName());
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretkey, ivspec);
            result = cipher.doFinal(plaintext);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
                | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            LOGGER.warn("Encountered exception while encrypting the StatePlaintext with " + cipherAlgorithm.name());
            LOGGER.debug(ex);
            throw new WorkflowExecutionException(
                    "Error while StatePlaintext Encryption. See Debug-Log for more Information.");
        }
        return result;
    }

    public static byte[] decrypt(CipherAlgorithm cipherAlgorithm, byte[] ciphertext, byte[] key, byte[] iv) {
        byte[] result = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm.getJavaName());
            BulkCipherAlgorithm bulkcipher = BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherAlgorithm);
            SecretKeySpec secretkey = new SecretKeySpec(key, bulkcipher.getJavaName());
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretkey, ivspec);
            result = cipher.doFinal(ciphertext);
            result = removePadding(result);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
                | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            LOGGER.warn("Encountered exception while encrypting the StatePlaintext with " + cipherAlgorithm.name());
            LOGGER.debug(ex);
            throw new WorkflowExecutionException(
                    "Error while StatePlaintext Decryption. See Debug-Log for more Information.");
        }
        return result;
    }

    public static byte[] generateHMAC(MacAlgorithm macAlgorithm, byte[] plaintext, byte[] key) {
        byte[] result = new byte[0];
        try {
            Mac mac = Mac.getInstance(macAlgorithm.getJavaName());
            SecretKeySpec macKey = new SecretKeySpec(key, macAlgorithm.getJavaName());
            mac.init(macKey);
            result = mac.doFinal(plaintext);
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            LOGGER.warn("Encountered exception while generating the HMAC " + macAlgorithm.name()
                    + " of an encryptedState.");
            LOGGER.debug(ex);
            throw new WorkflowExecutionException("Error while HMAC generation. See Debug-Log for more Information.");
        }
        return result;
    }

    public static boolean verifyHMAC(MacAlgorithm macalgo, byte[] mac, byte[] plaintext, byte[] key) {
        byte[] newmac = generateHMAC(macalgo, plaintext, key);
        boolean result = Arrays.equals(mac, newmac);
        return result;
    }

    private static byte[] addPadding(byte[] plaintextraw, int keysize) {
        byte padlen = (byte) (0xFF & (keysize - (plaintextraw.length % keysize)));
        byte[] padding = new byte[padlen];
        for (int i = 0; i < padlen; i++) {
            padding[i] = padlen;
        }
        byte[] padded = ArrayConverter.concatenate(plaintextraw, padding);
        return padded;
    }

    private static byte[] removePadding(byte[] result) {
        int padlen = result[result.length - 1];
        return Arrays.copyOf(result, result.length - padlen);
    }
}