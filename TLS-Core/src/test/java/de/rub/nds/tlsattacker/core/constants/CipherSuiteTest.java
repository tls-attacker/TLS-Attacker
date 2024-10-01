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

    @Test
    public void testIsRealCipherSuite() {

        assertTrue(CipherSuite.TLS_AES_128_CCM_8_SHA256.isRealCipherSuite());
        assertTrue(CipherSuite.TLS_AES_256_GCM_SHA384.isRealCipherSuite());
        assertFalse(CipherSuite.GREASE_03.isRealCipherSuite());
        assertFalse(CipherSuite.TLS_FALLBACK_SCSV.isRealCipherSuite());
    }

    @Test
    public void testgetCipherSuite() {

        assertTrue(CipherSuite.getCipherSuite(5) == CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        assertTrue(CipherSuite.getCipherSuite(8) == CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
        assertTrue(CipherSuite.getCipherSuite(13) == CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);

        assertTrue(CipherSuite.getCipherSuite(93) == null);
    }

    @Test
    public void testgetCipherSuiteByte() {

        assertTrue(
                CipherSuite.getCipherSuite(new byte[] {0, 1}) == CipherSuite.TLS_RSA_WITH_NULL_MD5);
        assertTrue(
                CipherSuite.getCipherSuite(new byte[] {0, 8})
                        == CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
        assertTrue(
                CipherSuite.getCipherSuite(new byte[] {0, 70})
                        == CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA);

        assertTrue(
                CipherSuite.getCipherSuite(new byte[] {(byte) 0xC0, (byte) 0x90})
                        == CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256);
        assertTrue(CipherSuite.getCipherSuite(new byte[] {0, 93}) == null);
    }
}
