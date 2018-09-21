/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.UnknownCiphersuiteException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class CipherSuiteTest {

    private static final Logger LOGGER = LogManager.getLogger();

    public CipherSuiteTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of getCiphersuites method, of class CipherSuite. size of Array % 2
     * == 0
     */
    @Test
    public void testPrepare1() {
        List<CipherSuite> cipherSuites = new LinkedList<>();
        byte[] values = ArrayConverter.hexStringToByteArray("00010002");
        cipherSuites = CipherSuite.getCiphersuites(values);
        assertEquals(2, cipherSuites.size());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0001"), cipherSuites.get(0).getByteValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0002"), cipherSuites.get(1).getByteValue());
    }

    /**
     * Test of getCiphersuites method, of class CipherSuite. size of Array % 2
     * != 0
     */
    @Test(expected = UnknownCiphersuiteException.class)
    public void testPrepare2() {
        List<CipherSuite> cipherSuites = new LinkedList<>();
        byte[] values = ArrayConverter.hexStringToByteArray("0001000200");
        cipherSuites = CipherSuite.getCiphersuites(values);
        assertEquals(2, cipherSuites.size());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0001"), cipherSuites.get(0).getByteValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0002"), cipherSuites.get(1).getByteValue());
    }

    @Test
    public void testUnimplemented() {
        for (CipherSuite suite : CipherSuite.getNotImplemented()) {
            LOGGER.debug(suite.name());
        }
        LOGGER.debug("Not implemented: " + CipherSuite.getNotImplemented().size());
        LOGGER.debug("Implemented: " + CipherSuite.getImplemented().size());
    }

    @Test
    public void implementedListContainsNoDuplicates() {
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            int counter = 0;
            for (CipherSuite tempCipherSuite : CipherSuite.getImplemented()) {
                if (suite == tempCipherSuite) {
                    counter++;
                }
            }
            if (counter != 1) {
                fail("" + suite + " is a duplicate in the getImplemented Ciphersuite list");
            }
        }
    }

    @Test
    public void testIsUsingMac() {
        assertTrue(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.isUsingMac());
        assertTrue(CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT.isUsingMac());
        assertTrue(CipherSuite.TLS_GOSTR341001_WITH_NULL_GOSTR3411.isUsingMac());
        assertTrue(CipherSuite.TLS_GOSTR341112_256_WITH_28147_CNT_IMIT.isUsingMac());

        assertFalse(CipherSuite.TLS_AES_256_GCM_SHA384.isUsingMac());
    }

}
