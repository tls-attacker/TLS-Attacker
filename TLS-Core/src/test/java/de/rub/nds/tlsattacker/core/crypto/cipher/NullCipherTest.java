/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class NullCipherTest {

    private final String strKey = "ExampleKey";
    private final String strMessage = "TestMessage";
    private final String strIV = "Vector for Testing";
    private final String strAuth = "AuthenticationData for Testing";
    private final int iTag = 256;
    private byte[] bKey;
    private byte[] bMessage;
    private byte[] bIV;
    private byte[] bAuth;

    @Before
    public void setUp() {
        bKey = strKey.getBytes();
        bMessage = strMessage.getBytes();
        bIV = strIV.getBytes();
        bAuth = strAuth.getBytes();
    }

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
    public void testEncryptionWithIvWithTagLengthWithAdditionAuthenticatedData() throws CryptoException {
        NullCipher cipher = new NullCipher();

        byte[] bEncrypted = cipher.encrypt(bIV, iTag, bAuth, bMessage);

        assertArrayEquals(bMessage, bEncrypted);
    }

    // decryption Tests

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
    public void testDecryptionWithIvWithTagLengthWithAdditionAuthenticatedData() throws CryptoException {
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
