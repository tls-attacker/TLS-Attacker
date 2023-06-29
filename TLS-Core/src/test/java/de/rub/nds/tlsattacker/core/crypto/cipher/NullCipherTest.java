/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import org.junit.jupiter.api.Test;

public class NullCipherTest {

    private final int iTag = 256;
    private final byte[] bKey = "ExampleKey".getBytes();
    private final byte[] bMessage = "TestMessage".getBytes();
    private final byte[] bIV = "Vector for Testing".getBytes();
    private final byte[] bAuth = "AuthenticationData for Testing".getBytes();

    // Encryption Tests

    @Test
    public void testEncryption() throws CryptoException {
        NullCipher cipher = new NullCipher();
        byte[] bEncrypted = cipher.encrypt(bKey, bMessage);
        assertArrayEquals(bMessage, bEncrypted);
    }

    @Test
    public void testEncryptionWithIv() throws CryptoException {
        NullCipher cipher = new NullCipher();
        byte[] bEncrypted = cipher.encrypt(bIV, bMessage);
        assertArrayEquals(bMessage, bEncrypted);
    }

    @Test
    public void testEncryptionWithIvWithTagLength() throws CryptoException {
        NullCipher cipher = new NullCipher();
        byte[] bEncrypted = cipher.encrypt(bIV, iTag, bMessage);
        assertArrayEquals(bMessage, bEncrypted);
    }

    @Test
    public void testEncryptionWithIvWithTagLengthWithAdditionAuthenticatedData()
            throws CryptoException {
        NullCipher cipher = new NullCipher();
        byte[] bEncrypted = cipher.encrypt(bIV, iTag, bAuth, bMessage);
        assertArrayEquals(bMessage, bEncrypted);
    }

    // Decryption Tests

    @Test
    public void testDecryption() throws CryptoException {
        NullCipher cipher = new NullCipher();
        byte[] bDecrypted = cipher.decrypt(bKey, bMessage);
        assertArrayEquals(bMessage, bDecrypted);
    }

    @Test
    public void testDecryptionWithIv() throws CryptoException {
        NullCipher cipher = new NullCipher();
        byte[] bDecrypted = cipher.decrypt(bIV, bMessage);
        assertArrayEquals(bMessage, bDecrypted);
    }

    @Test
    public void testDecryptionWithIvWithTagLength() throws CryptoException {
        NullCipher cipher = new NullCipher();
        byte[] bDecrypted = cipher.decrypt(bIV, iTag, bMessage);
        assertArrayEquals(bMessage, bDecrypted);
    }

    @Test
    public void testDecryptionWithIvWithTagLengthWithAdditionAuthenticatedData()
            throws CryptoException {
        NullCipher cipher = new NullCipher();
        byte[] bDecrypted = cipher.decrypt(bIV, iTag, bAuth, bMessage);
        assertArrayEquals(bMessage, bDecrypted);
    }

    // Test of Encryption and Decryption with setIV() between

    @Test
    public void testEncryptionWithSetIvWithDecryption() throws CryptoException {
        NullCipher cipher = new NullCipher();
        byte[] bEncrypted = cipher.encrypt(bIV, iTag, bAuth, bMessage);
        cipher.setIv(bAuth);
        byte[] bDecrypted = cipher.decrypt(bIV, iTag, bAuth, bEncrypted);
        assertArrayEquals(bMessage, bDecrypted);
    }
}
