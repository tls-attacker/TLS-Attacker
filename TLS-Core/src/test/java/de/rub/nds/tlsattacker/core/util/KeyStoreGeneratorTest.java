/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.modifiablevariable.util.BadRandom;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Random;
import org.junit.jupiter.api.Test;

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
