/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class JavaCipher extends BaseCipher {

    private Logger LOGGER = LogManager.getLogger();

    private final CipherAlgorithm algorithm;

    private byte[] iv;
    private byte[] key;

    // stream ciphers require a continuous state
    private boolean keepCipherState;

    private Cipher cipher = null;

    public JavaCipher(CipherAlgorithm algorithm, byte[] key, boolean keepCipherState) {
        this.algorithm = algorithm;
        this.key = key;
        this.keepCipherState = keepCipherState;
    }

    @Override
    public int getBlocksize() {
        return algorithm.getBlocksize();
    }

    @Override
    public byte[] encrypt(byte[] iv, byte[] someBytes) throws CryptoException {
        IvParameterSpec encryptIv = new IvParameterSpec(iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            String keySpecAlgorithm = BulkCipherAlgorithm.getBulkCipherAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), encryptIv);
            byte[] result = cipher.doFinal(someBytes);
            this.iv = cipher.getIV();
            return result;
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
            | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException
            | IllegalArgumentException ex) {
            throw new CryptoException("Could not initialize JavaCipher. "
                + "Did you forget to use UnlimitedStrengthEnabler/add BouncyCastleProvider?", ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] someBytes) throws CryptoException {
        try {
            if (cipher == null) {
                cipher = Cipher.getInstance(algorithm.getJavaName());
                String keySpecAlgorithm = BulkCipherAlgorithm.getBulkCipherAlgorithm(algorithm).getJavaName();
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm));
            }
            if (keepCipherState) {
                return cipher.update(someBytes);
            } else {
                return cipher.doFinal(someBytes);
            }
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
            | InvalidKeyException | NoSuchPaddingException | IllegalArgumentException ex) {
            throw new CryptoException("Could not encrypt data with: " + algorithm.getJavaName(), ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] someBytes) throws CryptoException {
        GCMParameterSpec encryptIv = new GCMParameterSpec(tagLength, iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            String keySpecAlgorithm = BulkCipherAlgorithm.getBulkCipherAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), encryptIv);
            byte[] result = cipher.doFinal(someBytes);
            this.iv = cipher.getIV();
            return result;
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
            | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException
            | IllegalArgumentException ex) {
            throw new CryptoException("Could not encrypt data with " + algorithm.getJavaName(), ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes)
        throws CryptoException {
        GCMParameterSpec encryptIv = new GCMParameterSpec(tagLength, iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());

            String keySpecAlgorithm = BulkCipherAlgorithm.getBulkCipherAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), encryptIv);
            cipher.updateAAD(additionAuthenticatedData);
            byte[] result = cipher.doFinal(someBytes);
            this.iv = cipher.getIV();
            return result;
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
            | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException
            | IllegalArgumentException ex) {
            throw new CryptoException("Could not encrypt data with " + algorithm.getJavaName(), ex);
        }
    }

    @Override
    public byte[] getIv() {
        return iv;
    }

    @Override
    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    @Override
    public byte[] decrypt(byte[] iv, byte[] someBytes) throws CryptoException {
        IvParameterSpec decryptIv = new IvParameterSpec(iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            String keySpecAlgorithm = BulkCipherAlgorithm.getBulkCipherAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), decryptIv);
            byte[] result = cipher.doFinal(someBytes);
            if (result.length >= getBlocksize()) {
                this.iv = new byte[getBlocksize()];
                System.arraycopy(someBytes, someBytes.length - getBlocksize(), this.iv, 0, getBlocksize());
            }
            return result;
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
            | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException ex) {
            throw new CryptoException("Could not decrypt data", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] someBytes) throws CryptoException {
        try {
            if (cipher == null) {
                cipher = Cipher.getInstance(algorithm.getJavaName());
                String keySpecAlgorithm = BulkCipherAlgorithm.getBulkCipherAlgorithm(algorithm).getJavaName();
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm));
            }

            if (keepCipherState) {
                return cipher.update(someBytes);
            } else {
                return cipher.doFinal(someBytes);
            }
        } catch (IllegalStateException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
            | IllegalBlockSizeException | BadPaddingException ex) {
            throw new CryptoException("Could not decrypt data", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] someBytes) throws CryptoException {
        GCMParameterSpec decryptIv = new GCMParameterSpec(tagLength, iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            String keySpecAlgorithm = BulkCipherAlgorithm.getBulkCipherAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), decryptIv);
            byte[] result = cipher.doFinal(someBytes);
            if (result.length >= getBlocksize()) {
                this.iv = new byte[getBlocksize()];
                System.arraycopy(someBytes, someBytes.length - getBlocksize(), this.iv, 0, getBlocksize());
            }
            return result;
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
            | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException ex) {
            throw new CryptoException("Could not decrypt data", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] additionalAuthenticatedData, byte[] cipherText)
        throws CryptoException {
        GCMParameterSpec decryptIv = new GCMParameterSpec(tagLength, iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            String keySpecAlgorithm = BulkCipherAlgorithm.getBulkCipherAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), decryptIv);
            cipher.updateAAD(additionalAuthenticatedData);
            byte[] result = cipher.doFinal(cipherText);
            if (result.length >= getBlocksize()) {
                this.iv = new byte[getBlocksize()];
                System.arraycopy(cipherText, cipherText.length - getBlocksize(), this.iv, 0, getBlocksize());
            }
            return result;
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
            | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException
            | IllegalArgumentException ex) {
            throw new CryptoException("Could not decrypt data", ex);
        }
    }
}
