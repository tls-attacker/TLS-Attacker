/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class BouncyCastleProviderCheckerTest {
    @Before
    public void setUp() {
        Security.removeProvider("BC");
    }

    @After
    public void tearDown() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test of isLoaded method, of class BouncyCastleProviderChecker.
     */
    @Test
    public void testIsLoaded() {
        assertFalse(BouncyCastleProviderChecker.isLoaded());
        Security.addProvider(new BouncyCastleProvider());
        assertTrue(BouncyCastleProviderChecker.isLoaded());
    }

}
