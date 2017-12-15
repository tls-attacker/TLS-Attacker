/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Pierre Tilhaus
 */
public class DHEServerKeyExchangeMessageTest {

    DHEServerKeyExchangeMessage message;

    @Before
    public void setUp() {
        message = new DHEServerKeyExchangeMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getModulus method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetModulus() {
    }

    /**
     * Test of setModulus method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetModulus_ModifiableByteArray() {
    }

    /**
     * Test of setModulus method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetModulus_byteArr() {
    }

    /**
     * Test of getGenerator method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetGenerator() {
    }

    /**
     * Test of setGenerator method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetGenerator_ModifiableByteArray() {
    }

    /**
     * Test of setGenerator method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetGenerator_byteArr() {
    }

    /**
     * Test of getModulusLength method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetModulusLength() {
    }

    /**
     * Test of setModulusLength method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetModulusLength_ModifiableInteger() {
    }

    /**
     * Test of setModulusLength method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetModulusLength_int() {
    }

    /**
     * Test of getGeneratorLength method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetGeneratorLength() {
    }

    /**
     * Test of setGeneratorLength method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetGeneratorLength_ModifiableInteger() {
    }

    /**
     * Test of setGeneratorLength method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetGeneratorLength_int() {
    }

    /**
     * Test of getComputations method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetComputations() {
    }

    /**
     * Test of toString method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nDHEServerKeyExchangeMessage:");
        sb.append("\n  Modulus p: ").append("null");
        sb.append("\n  Generator g: ").append("null");
        sb.append("\n  Public Key: ").append("null");
        sb.append("\n  Signature and Hash Algorithm: ").append("null");
        sb.append("\n  Signature: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getHandler method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of toCompactString method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testToCompactString() {
    }

    /**
     * Test of prepareComputations method, of class DHEServerKeyExchangeMessage.
     */
    @Test
    public void testPrepareComputations() {
    }

    /**
     * Test of getAllModifiableVariableHolders method, of class
     * DHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetAllModifiableVariableHolders() {
    }

}
