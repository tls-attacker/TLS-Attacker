/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.modifiablevariable.util.BadRandom;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Random;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

public class KeyStoreGeneratorTest {

    private final BadRandom random = new BadRandom(new Random(0), null);

    /**
     * Test of createRSAKeyPair method, of class KeyStoreGenerator.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testCreateRSAKeyPair() throws Exception {
        KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, random);
        assertNotNull(k);
        assertEquals("RSA", k.getPublic().getAlgorithm());
    }

    /**
     * Test of createECKeyPair method, of class KeyStoreGenerator.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testCreateECKeyPair() throws Exception {
        KeyPair k = KeyStoreGenerator.createECKeyPair(256, random);
        assertNotNull(k);
        assertEquals("EC", k.getPublic().getAlgorithm());
    }

    /**
     * Test of createKeyStore method, of class KeyStoreGenerator.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testCreateKeyStore() throws Exception {
        KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, random);
        KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
        assertNotNull(ks);

        k = KeyStoreGenerator.createECKeyPair(256, random);
        ks = KeyStoreGenerator.createKeyStore(k, random);
        assertNotNull(ks);
    }

}
