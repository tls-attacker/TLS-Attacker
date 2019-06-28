/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 *
 */
public class Pkcs1VectorGenerator {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Generates different encrypted PKCS1 vectors
     *
     * @param publicKey
     *            The publickey
     * @param type
     *            the type
     * @param protocolVersion
     * @return encrypted pkcs1Vectors
     */
    public static List<Pkcs1Vector> generatePkcs1Vectors(RSAPublicKey publicKey, BleichenbacherCommandConfig.Type type,
            ProtocolVersion protocolVersion) {
        List<Pkcs1Vector> encryptedVectors = generatePlainPkcs1Vectors(publicKey.getModulus().bitLength(), type,
                protocolVersion);
        try {
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            // encrypt all the padded keys
            for (Pkcs1Vector vector : encryptedVectors) {
                byte[] encrypted = rsa.doFinal(vector.getPlainValue());
                vector.setEncryptedValue(encrypted);
            }
            return encryptedVectors;
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException
                | NoSuchPaddingException ex) {
            throw new ConfigurationException("The different PKCS#1 attack vectors could not be generated.", ex);
        }
    }

    /**
     *
     * @param publicKey
     * @param protocolVersion
     * @return
     */
    public static Pkcs1Vector generateCorrectPkcs1Vector(RSAPublicKey publicKey, ProtocolVersion protocolVersion) {
        Pkcs1Vector encryptedVector = getPlainCorrect(publicKey.getModulus().bitLength(), protocolVersion);
        try {
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            // encrypt all the padded keys
            byte[] encrypted = rsa.doFinal(encryptedVector.getPlainValue());
            encryptedVector.setEncryptedValue(encrypted);
            return encryptedVector;
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException
                | NoSuchPaddingException ex) {
            throw new ConfigurationException("The PKCS#1 attack vectors could not be generated.", ex);
        }
    }

    /**
     * Generates different plain PKCS1 vectors
     *
     * @param publicKeyBitLength
     *            The publicKeyBitLength
     * @param type
     *            the type
     * @param protocolVersion
     * @return pkcs1Vectors
     */
    public static List<Pkcs1Vector> generatePlainPkcs1Vectors(int publicKeyBitLength,
            BleichenbacherCommandConfig.Type type, ProtocolVersion protocolVersion) {
        byte[] keyBytes = new byte[HandshakeByteLength.PREMASTER_SECRET];
        Arrays.fill(keyBytes, (byte) 42);
        keyBytes[0] = protocolVersion.getMajor();
        keyBytes[1] = protocolVersion.getMinor();
        int publicKeyByteLength = publicKeyBitLength / 8;

        // create plain padded keys
        List<Pkcs1Vector> pkcs1Vectors = new LinkedList<>();
        pkcs1Vectors.add(new Pkcs1Vector("Correctly formatted PKCS#1 PMS message", getPaddedKey(publicKeyByteLength,
                keyBytes)));
        pkcs1Vectors.add(new Pkcs1Vector("Wrong first byte (0x00 set to 0x17)", getEK_WrongFirstByte(
                publicKeyByteLength, keyBytes)));
        pkcs1Vectors.add(new Pkcs1Vector("Wrong second byte (0x02 set to 0x17)", getEK_WrongSecondByte(
                publicKeyByteLength, keyBytes)));
        pkcs1Vectors.add(new Pkcs1Vector("Invalid TLS version in PMS", getEK_WrongTlsVersion(publicKeyByteLength,
                keyBytes)));
        pkcs1Vectors.add(new Pkcs1Vector("Correctly formatted PKCS#1 PMS message, but 1 byte shorter", getPaddedKey(
                publicKeyByteLength - 1, keyBytes)));
        pkcs1Vectors.add(new Pkcs1Vector("No 0x00 in message", getEK_NoNullByte(publicKeyByteLength, keyBytes)));
        pkcs1Vectors.add(new Pkcs1Vector("0x00 in PKCS#1 padding (first 8 bytes after 0x00 0x02)",
                getEK_NullByteInPkcsPadding(publicKeyByteLength, keyBytes)));
        pkcs1Vectors.add(new Pkcs1Vector("0x00 in some padding byte", getEK_NullByteInPadding(publicKeyByteLength,
                keyBytes)));
        pkcs1Vectors.add(new Pkcs1Vector("0x00 on the last position  (|PMS| = 0)", getEK_SymmetricKeyOfSize(
                publicKeyByteLength, keyBytes, 0)));
        pkcs1Vectors.add(new Pkcs1Vector("0x00 on the next to last position (|PMS| = 1)", getEK_SymmetricKeyOfSize(
                publicKeyByteLength, keyBytes, 1)));
        pkcs1Vectors.add(new Pkcs1Vector("Correctly formatted PKCS#1 message, (|PMS| = 47)", getPaddedKey(
                publicKeyByteLength, Arrays.copyOf(keyBytes, HandshakeByteLength.PREMASTER_SECRET - 1))));
        pkcs1Vectors.add(new Pkcs1Vector("Correctly formatted PKCS#1 message, (|PMS| = 49)", getPaddedKey(
                publicKeyByteLength, Arrays.copyOf(keyBytes, HandshakeByteLength.PREMASTER_SECRET + 1))));

        if (type == BleichenbacherCommandConfig.Type.FULL) {
            List<Pkcs1Vector> additionalVectors = getEK_DifferentPositionsOf0x00(publicKeyByteLength, keyBytes);
            for (Pkcs1Vector vector : additionalVectors) {
                pkcs1Vectors.add(vector);
            }
        }
        return pkcs1Vectors;
    }

    private static Pkcs1Vector getPlainCorrect(int publicKeyBitLength, ProtocolVersion protocolVersion) {
        byte[] keyBytes = new byte[HandshakeByteLength.PREMASTER_SECRET];
        Arrays.fill(keyBytes, (byte) 42);
        keyBytes[0] = protocolVersion.getMajor();
        keyBytes[1] = protocolVersion.getMinor();
        int publicKeyByteLength = publicKeyBitLength / 8;
        return new Pkcs1Vector("Correctly formatted PKCS#1 PMS message", getPaddedKey(publicKeyByteLength, keyBytes));
    }

    /**
     * Generates a validly padded message
     *
     * @param rsaKeyLength
     *            rsa key length in bytes
     * @param symmetricKey
     *            symmetric key to be padded
     * @return padded key
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

    private static byte[] getEK_WrongTlsVersion(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[rsaKeyLength - symmetricKey.length] = 0x42;
        key[rsaKeyLength - symmetricKey.length + 1] = 0x42;
        LOGGER.debug("Generated a PKCS1 padded message with a wrong TLS version bytes: {}",
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
     *            rsakeylength
     * @param symmetricKey
     *            symmetric key
     * @return Pkcs1Vectors
     */
    private static List<Pkcs1Vector> getEK_DifferentPositionsOf0x00(int rsaKeyLength, byte[] symmetricKey) {
        List<Pkcs1Vector> vectors = new LinkedList<>();
        for (int i = 2; i < rsaKeyLength; i++) {
            // generate padded key
            byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
            // remove 0x00
            for (int j = 3; j < key.length; j++) {
                if (key[j] == 0x00) {
                    key[j] = 0x01;
                }
            }
            key[i] = 0x00;
            vectors.add(new Pkcs1Vector(("0x00 on a wrong position (" + i + ")"), key));
        }
        LOGGER.debug("Generated PKCS1 vectors with different invalid 0x00 positions");
        return vectors;
    }

    /**
     * No instantiation needed, only one static method used
     */
    private Pkcs1VectorGenerator() {
    }
}
