/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ChaCha20Poly1305CipherTest {

    @BeforeClass
    public static void setUp() {
    }

    @Test
    public void testEncrypt() {
        byte[] nonce = new byte[8];
        byte[] iv = ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray("DB9225611E4646D7D10BA135"), nonce);
        byte[] key = ArrayConverter
                .hexStringToByteArray("5C602601DBAC4CD0B8BA794A208763A8036C239C91835BA8FD4396B34F004F3A");
        byte[] aad = ArrayConverter.hexStringToByteArray("00000000000000001603030010");
        byte[] plaintext = ArrayConverter.hexStringToByteArray("1400000C910399922449024F3C8006EF");
        byte[] expectedCiphertext = ArrayConverter
                .hexStringToByteArray("ACE73C8630758D6DBFCEF6D1A0318D4F85BA532C183455F27E00618365DE1A57");

        ChaCha20Poly1305Cipher encryptCipher = new ChaCha20Poly1305Cipher(key); //
        byte[] calculatedCiphertext = encryptCipher.encrypt(iv, 16, aad, plaintext);

        Assert.assertArrayEquals(expectedCiphertext, calculatedCiphertext);
    }

    @Test
    public void testDecrypt() {
        byte[] nonce = new byte[8];
        byte[] iv = ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray("FC8A9AA4809FB4F11B5E6E2B"), nonce);
        byte[] key = ArrayConverter
                .hexStringToByteArray("7A3B05D1E2A054BB00ED2E308463D4AA258C1E54F946898919B059765B8636DD");
        byte[] aad = ArrayConverter.hexStringToByteArray("00000000000000001603030010");
        byte[] ciphertext = ArrayConverter
                .hexStringToByteArray("C11D4D4DE0E1B97DFA9BB935A7E072B27EB0FD0483F8586842155D48CBC552FD");
        byte[] expectedPlaintext = ArrayConverter.hexStringToByteArray("1400000C5C2BB43710C69470E41B058C");

        ChaCha20Poly1305Cipher decryptCipher = new ChaCha20Poly1305Cipher(key); //
        byte[] calculatedPlaintext = decryptCipher.decrypt(iv, 16, aad, ciphertext);

        Assert.assertArrayEquals(expectedPlaintext, calculatedPlaintext);
    }

}
