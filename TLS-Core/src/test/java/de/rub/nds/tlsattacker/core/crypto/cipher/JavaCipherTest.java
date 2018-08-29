/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.security.Security;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author robert
 */
public class JavaCipherTest {

    public JavaCipherTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void generalTest() {
        Random r = new Random(0);
        for (CipherAlgorithm algo : CipherAlgorithm.values()) {

            byte[] key = new byte[algo.getKeySize()];
            r.nextBytes(key);
            JavaCipher cipher = new JavaCipher(algo, key);

            byte[] plaintext = new byte[algo.getBlocksize()];
            r.nextBytes(plaintext);

            try {
                cipher.encrypt(plaintext);
                System.out.println(algo.name() + " worked!");
            } catch (Exception ex) {
                System.out.println(algo.name() + " did not work!");
                ex.printStackTrace();
            }
        }
    }
}
