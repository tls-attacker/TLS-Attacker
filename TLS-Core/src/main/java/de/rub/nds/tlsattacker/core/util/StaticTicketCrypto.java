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

    public static byte[] encryptAES_128_CBC(byte[] plaintextUnpadded, byte[] key, byte[] iv) {
        byte[] result = new byte[0];
        byte[] plaintext = addPadding(plaintextUnpadded);
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec aeskey = new SecretKeySpec(key, "AES");
            IvParameterSpec aesiv = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, aeskey, aesiv);
            result = cipher.doFinal(plaintext);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
                | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            // TODO: Check kind of used error handling. (Should I pass through
            // the Exception or return wrong Data?)
            LOGGER.warn("Encountered exception while encrypting the StatePlaintext with AES128 CBC.");
            LOGGER.debug(ex);
        }
        return result;
    }

    public static byte[] decryptAES_128_CBC(byte[] ciphertext, byte[] key, byte[] iv) {
        byte[] result = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec aeskey = new SecretKeySpec(key, "AES");
            IvParameterSpec aesiv = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, aeskey, aesiv);
            result = cipher.doFinal(ciphertext);
            result = removePadding(result);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
                | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException ex) {
            // TODO: Check kind of used error handling. (Should I pass through
            // the Exception or return wrong Data?)
            LOGGER.warn("Encountered exception while encrypting the StatePlaintext with AES128 CBC.");
            LOGGER.debug(ex);
        }
        return result;
    }

    public static byte[] generateHMAC_SHA256(byte[] plaintext, byte[] key) {
        byte[] result = new byte[0];
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec macKey = new SecretKeySpec(key, "HmacSHA256");
            mac.init(macKey);
            result = mac.doFinal(plaintext);
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            // TODO: Check kind of used error handling. (Should I pass through
            // the Exception or return wrong Data?)
            LOGGER.warn("Encountered exception while generating the HMAC SHA256 of an encryptedState.");
            LOGGER.debug(ex);
        }
        return result;
    }

    public static boolean verifyHMAC_SHA256(byte[] mac, byte[] plaintext, byte[] key) {
        byte[] newmac = generateHMAC_SHA256(plaintext, key);
        boolean result = Arrays.equals(mac, newmac);
        return result;
    }

    private static byte[] addPadding(byte[] plaintextraw) {
        byte padlen = (byte) (0xFF & (16 - (plaintextraw.length % 16)));
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