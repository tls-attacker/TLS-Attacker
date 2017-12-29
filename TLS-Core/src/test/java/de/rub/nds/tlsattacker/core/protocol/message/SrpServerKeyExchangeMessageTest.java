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
 * @author Pierre Tilhaus <pierre.tilhaus@rub.de>
 */
public class SrpServerKeyExchangeMessageTest {

    SrpServerKeyExchangeMessage message;

    @Before
    public void setUp() {
        message = new SrpServerKeyExchangeMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getModulus method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testGetModulus() {
    }

    /**
     * Test of setModulus method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetModulus_ModifiableByteArray() {
    }

    /**
     * Test of setModulus method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetModulus_byteArr() {
    }

    /**
     * Test of getSalt method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testGetSalt() {
    }

    /**
     * Test of setSalt method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetSalt_ModifiableByteArray() {
    }

    /**
     * Test of setSalt method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetSalt_byteArr() {
    }

    /**
     * Test of getSaltLength method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testGetSaltLength() {
    }

    /**
     * Test of setSaltLength method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetSaltLength_ModifiableInteger() {
    }

    /**
     * Test of setSaltLength method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetSaltLength_int() {
    }

    /**
     * Test of getGenerator method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testGetGenerator() {
    }

    /**
     * Test of setGenerator method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetGenerator_ModifiableByteArray() {
    }

    /**
     * Test of setGenerator method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetGenerator_byteArr() {
    }

    /**
     * Test of getModulusLength method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testGetModulusLength() {
    }

    /**
     * Test of setModulusLength method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetModulusLength_ModifiableInteger() {
    }

    /**
     * Test of setModulusLength method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetModulusLength_int() {
    }

    /**
     * Test of getGeneratorLength method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testGetGeneratorLength() {
    }

    /**
     * Test of setGeneratorLength method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetGeneratorLength_ModifiableInteger() {
    }

    /**
     * Test of setGeneratorLength method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testSetGeneratorLength_int() {
    }

    /**
     * Test of getComputations method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testGetComputations() {
    }

    /**
     * Test of toString method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nSrpServerKeyExchangeMessage:");
        sb.append("\n  Modulus p: ").append("null");
        sb.append("\n  Generator g: ").append("null");
        sb.append("\n  Public Key: ").append("null");
        sb.append("\n  Signature and Hash Algorithm: ").append("null");
        sb.append("\n  Signature: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getHandler method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of toCompactString method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testToCompactString() {
    }

    /**
     * Test of prepareComputations method, of class SrpServerKeyExchangeMessage.
     */
    @Test
    public void testPrepareComputations() {
    }

    /**
     * Test of getAllModifiableVariableHolders method, of class
     * SrpServerKeyExchangeMessage.
     */
    @Test
    public void testGetAllModifiableVariableHolders() {
    }

}
