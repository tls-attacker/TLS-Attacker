/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.UnknownCipherSuiteException;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

public class CipherSuiteTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Test of getCipherSuites method, of class CipherSuite. size of Array % 2 == 0 */
    @Test
    public void testPrepareEvenLength() {
        byte[] values = ArrayConverter.hexStringToByteArray("00010002");
        List<CipherSuite> cipherSuites = CipherSuite.getCipherSuites(values);
        assertEquals(2, cipherSuites.size());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0001"), cipherSuites.get(0).getByteValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0002"), cipherSuites.get(1).getByteValue());
    }

    /** Test of getCipherSuites method, of class CipherSuite. size of Array % 2 != 0 */
    @Test
    public void testPrepareOddLengthThrows() {
        byte[] values = ArrayConverter.hexStringToByteArray("0001000200");
        assertThrows(UnknownCipherSuiteException.class, () -> CipherSuite.getCipherSuites(values));
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
        List<CipherSuite> implementedCipherSuites = CipherSuite.getImplemented();
        List<CipherSuite> distinctCipherSuites =
                CipherSuite.getImplemented().stream().distinct().collect(Collectors.toList());
        if (implementedCipherSuites.size() != distinctCipherSuites.size()) {
            fail("The getImplemented cipher suite list contains duplicate elements");
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
