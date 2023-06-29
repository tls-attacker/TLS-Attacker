/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BouncyCastleProviderCheckerTest {
    @BeforeEach
    public void setUp() {
        Security.removeProvider("BC");
    }

    @AfterEach
    public void tearDown() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Test of isLoaded method, of class BouncyCastleProviderChecker. */
    @Test
    public void testIsLoaded() {
        assertFalse(BouncyCastleProviderChecker.isLoaded());
        Security.addProvider(new BouncyCastleProvider());
        assertTrue(BouncyCastleProviderChecker.isLoaded());
    }
}
