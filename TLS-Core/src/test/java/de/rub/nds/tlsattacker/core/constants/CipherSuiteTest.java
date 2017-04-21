/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.UnknownCiphersuiteException;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class CipherSuiteTest {

    public CipherSuiteTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of getCiphersuites method, of class CipherSuite.
     * 
     * size of Array % 2 == 0
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
     * Test of getCiphersuites method, of class CipherSuite.
     * 
     * size of Array % 2 != 0
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

}
