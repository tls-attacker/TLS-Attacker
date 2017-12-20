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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Pierre Tilhaus
 */
public class PskServerKeyExchangeMessageTest {

    PskServerKeyExchangeMessage message;

    @Before
    public void setUp() {
        message = new PskServerKeyExchangeMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getIdentityHint method, of class PskServerKeyExchangeMessage.
     */
    @Test
    public void testGetIdentityHint() {
    }

    /**
     * Test of setIdentityHint method, of class PskServerKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityHint_ModifiableByteArray() {
    }

    /**
     * Test of setIdentityHint method, of class PskServerKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityHint_byteArr() {
    }

    /**
     * Test of getIdentityHintLength method, of class
     * PskServerKeyExchangeMessage.
     */
    @Test
    public void testGetIdentityHintLength() {
    }

    /**
     * Test of setIdentityHintLength method, of class
     * PskServerKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityHintLength_ModifiableInteger() {
    }

    /**
     * Test of setIdentityHintLength method, of class
     * PskServerKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityHintLength_int() {
    }

    /**
     * Test of getComputations method, of class PskServerKeyExchangeMessage.
     */
    @Test
    public void testGetComputations() {
    }

    /**
     * Test of toString method, of class PskServerKeyExchangeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nPskServerKeyExchangeMessage:");
        sb.append("\n  IdentityHintLength: ").append("null");
        sb.append("\n  IdentityHint: ").append("null");

        Assert.assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getHandler method, of class PskServerKeyExchangeMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of toCompactString method, of class PskServerKeyExchangeMessage.
     */
    @Test
    public void testToCompactString() {
    }

    /**
     * Test of prepareComputations method, of class PskServerKeyExchangeMessage.
     */
    @Test
    public void testPrepareComputations() {
    }

    /**
     * Test of getAllModifiableVariableHolders method, of class
     * PskServerKeyExchangeMessage.
     */
    @Test
    public void testGetAllModifiableVariableHolders() {
    }

}
