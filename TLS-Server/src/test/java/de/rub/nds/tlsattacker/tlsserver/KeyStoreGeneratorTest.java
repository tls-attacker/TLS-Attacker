/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tlsserver;

import java.security.KeyPair;
import java.security.KeyStore;
import org.junit.Test;
import static org.junit.Assert.*;

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
