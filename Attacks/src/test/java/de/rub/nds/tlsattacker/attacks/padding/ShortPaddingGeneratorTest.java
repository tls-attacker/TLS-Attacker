/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
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
public class ShortPaddingGeneratorTest {

    private ShortPaddingGenerator generator;

    public ShortPaddingGeneratorTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        generator = new ShortPaddingGenerator();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testGetVectors() {
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isCBC()) {
                System.out.println(suite.name());
                generator.getVectors(suite, ProtocolVersion.TLS10);
                generator.getVectors(suite, ProtocolVersion.TLS11);
                generator.getVectors(suite, ProtocolVersion.TLS12);
            }
        }
    }

}
