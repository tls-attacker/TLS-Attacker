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
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.security.Security;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author robert
 */
public class JavaCipherTest {

    private final static Logger LOGGER = LogManager.getLogger();

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    public JavaCipherTest() {
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
                cipher.encrypt(key, plaintext);
            } catch (Exception ex) {
                LOGGER.error(ex);
            }
        }
    }
}
