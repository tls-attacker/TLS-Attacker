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
public class ECDHEServerKeyExchangeMessageTest {

    ECDHEServerKeyExchangeMessage message;

    @Before
    public void setUp() {
        message = new ECDHEServerKeyExchangeMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getCurveType method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetCurveType() {
    }

    /**
     * Test of setCurveType method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetCurveType_ModifiableByte() {
    }

    /**
     * Test of setCurveType method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetCurveType_byte() {
    }

    /**
     * Test of getNamedCurve method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetNamedCurve() {
    }

    /**
     * Test of setNamedCurve method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetNamedCurve_ModifiableByteArray() {
    }

    /**
     * Test of setNamedCurve method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testSetNamedCurve_byteArr() {
    }

    /**
     * Test of toString method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nECDHEServerKeyExchangeMessage:");
        sb.append("\n  Curve Type: ").append("null");
        sb.append("\n  Named Curve: ").append("null");
        sb.append("\n  Public Key: ").append("null");
        sb.append("\n  Signature and Hash Algorithm: ").append("null");
        sb.append("\n  Signature: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getComputations method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetComputations() {
    }

    /**
     * Test of getHandler method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of toCompactString method, of class ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testToCompactString() {
    }

    /**
     * Test of prepareComputations method, of class
     * ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testPrepareComputations() {
    }

    /**
     * Test of getAllModifiableVariableHolders method, of class
     * ECDHEServerKeyExchangeMessage.
     */
    @Test
    public void testGetAllModifiableVariableHolders() {
    }

}
