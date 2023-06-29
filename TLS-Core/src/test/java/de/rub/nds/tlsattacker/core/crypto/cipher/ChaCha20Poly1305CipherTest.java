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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import org.junit.jupiter.api.Test;

public class ChaCha20Poly1305CipherTest {

    @Test
    public void testEncrypt() {
        byte[] iv = ArrayConverter.hexStringToByteArray("DB9225611E4646D7D10BA135");
        byte[] key =
                ArrayConverter.hexStringToByteArray(
                        "5C602601DBAC4CD0B8BA794A208763A8036C239C91835BA8FD4396B34F004F3A");
        byte[] aad = ArrayConverter.hexStringToByteArray("00000000000000001603030010");
        byte[] plaintext = ArrayConverter.hexStringToByteArray("1400000C910399922449024F3C8006EF");
        byte[] expectedCiphertext =
                ArrayConverter.hexStringToByteArray(
                        "ACE73C8630758D6DBFCEF6D1A0318D4F85BA532C183455F27E00618365DE1A57");

        ChaCha20Poly1305Cipher encryptCipher = new StandardizedChaCha20Poly1305Cipher(key);
        byte[] calculatedCiphertext = encryptCipher.encrypt(iv, 16 * 8, aad, plaintext);

        assertArrayEquals(expectedCiphertext, calculatedCiphertext);
    }

    @Test
    public void testDecrypt() {
        try {
            byte[] iv = ArrayConverter.hexStringToByteArray("FC8A9AA4809FB4F11B5E6E2B");
            byte[] key =
                    ArrayConverter.hexStringToByteArray(
                            "7A3B05D1E2A054BB00ED2E308463D4AA258C1E54F946898919B059765B8636DD");
            byte[] aad = ArrayConverter.hexStringToByteArray("00000000000000001603030010");
            byte[] ciphertext =
                    ArrayConverter.hexStringToByteArray(
                            "C11D4D4DE0E1B97DFA9BB935A7E072B27EB0FD0483F8586842155D48CBC552FD");
            byte[] expectedPlaintext =
                    ArrayConverter.hexStringToByteArray("1400000C5C2BB43710C69470E41B058C");

            ChaCha20Poly1305Cipher decryptCipher = new StandardizedChaCha20Poly1305Cipher(key);
            byte[] calculatedPlaintext = decryptCipher.decrypt(iv, 16 * 8, aad, ciphertext);

            assertArrayEquals(expectedPlaintext, calculatedPlaintext);
        } catch (CryptoException ex) {
            throw new AssertionError("CryptoException: " + ex.getMessage());
        }
    }

    @Test
    public void testDecryptOldChaCha() {
        try {
            byte[] iv = ArrayConverter.hexStringToByteArray("cd7cf67be39c794a");
            byte[] key =
                    ArrayConverter.hexStringToByteArray(
                            "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007");
            byte[] aad = ArrayConverter.hexStringToByteArray("87e229d4500845a079c0");
            byte[] ciphertext =
                    ArrayConverter.hexStringToByteArray(
                            "e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6");
            byte[] expectedPlaintext = ArrayConverter.hexStringToByteArray("86d09974840bded2a5ca");

            ChaCha20Poly1305Cipher decryptCipher = new UnofficialChaCha20Poly1305Cipher(key);
            byte[] calculatedPlaintext = decryptCipher.decrypt(iv, 16 * 8, aad, ciphertext);
            assertArrayEquals(expectedPlaintext, calculatedPlaintext);
        } catch (CryptoException ex) {
            throw new AssertionError("CryptoException: " + ex.getMessage());
        }
    }

    @Test
    public void testEncryptOldChaCha() {
        byte[] iv = ArrayConverter.hexStringToByteArray("cd7cf67be39c794a");
        byte[] key =
                ArrayConverter.hexStringToByteArray(
                        "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007");
        byte[] aad = ArrayConverter.hexStringToByteArray("87e229d4500845a079c0");
        byte[] plaintext = ArrayConverter.hexStringToByteArray("86d09974840bded2a5ca");
        byte[] expectedCiphertext =
                ArrayConverter.hexStringToByteArray(
                        "e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6");

        ChaCha20Poly1305Cipher encryptCipher = new UnofficialChaCha20Poly1305Cipher(key);
        byte[] calculatedCiphertext = encryptCipher.encrypt(iv, 16 * 8, aad, plaintext);
        assertArrayEquals(expectedCiphertext, calculatedCiphertext);
    }
}
