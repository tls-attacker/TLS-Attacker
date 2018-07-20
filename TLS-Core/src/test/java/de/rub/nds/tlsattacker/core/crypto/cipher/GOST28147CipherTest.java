/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 * <p>
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class GOST28147CipherTest {

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testEncryptAndDecrypt() throws CryptoException {
        byte[] iv = new byte[8];
        byte[] key = ArrayConverter.hexStringToByteArray("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
        byte[] plaintext = "The quick brown fox jumps over the lazy dog\n".getBytes();
        byte[] expectedCiphertext = ArrayConverter.hexStringToByteArray("bcb821452e459f10f92019171e7c3b27b87f24b174306667f67704812c07b70b5e7420f74a9d54feb4897df8");

        GOST28147Cipher cipher = new GOST28147Cipher(CipherAlgorithm.GOST_28147_CNT, key, iv);
        byte[] actual = cipher.encrypt(plaintext);
        Assert.assertArrayEquals(expectedCiphertext, actual);

        cipher = new GOST28147Cipher(CipherAlgorithm.GOST_28147_CNT, key, iv);
        actual = cipher.decrypt(actual);
        Assert.assertArrayEquals(plaintext, actual);
    }

}
