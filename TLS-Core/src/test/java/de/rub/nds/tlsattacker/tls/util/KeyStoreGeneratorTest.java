/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.util;

import java.security.KeyPair;
import java.security.KeyStore;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class KeyStoreGeneratorTest {

    public KeyStoreGeneratorTest() {
    }

    /**
     * Test of createRSAKeyPair method, of class KeyStoreGenerator.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testCreateRSAKeyPair() throws Exception {
        KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
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
        KeyPair k = KeyStoreGenerator.createECKeyPair(256);
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
        KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
        KeyStore ks = KeyStoreGenerator.createKeyStore(k);
        assertNotNull(ks);

        k = KeyStoreGenerator.createECKeyPair(256);
        ks = KeyStoreGenerator.createKeyStore(k);
        assertNotNull(ks);
    }

}
