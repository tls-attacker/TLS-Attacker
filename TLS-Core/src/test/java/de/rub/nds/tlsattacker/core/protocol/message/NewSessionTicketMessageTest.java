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
public class NewSessionTicketMessageTest {

    NewSessionTicketMessage message;

    @Before
    public void setUp() {
        message = new NewSessionTicketMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getTicketLifetimeHint method, of class NewSessionTicketMessage.
     */
    @Test
    public void testGetTicketLifetimeHint() {
    }

    /**
     * Test of setTicketLifetimeHint method, of class NewSessionTicketMessage.
     */
    @Test
    public void testSetTicketLifetimeHint_ModifiableLong() {
    }

    /**
     * Test of setTicketLifetimeHint method, of class NewSessionTicketMessage.
     */
    @Test
    public void testSetTicketLifetimeHint_long() {
    }

    /**
     * Test of getTicket method, of class NewSessionTicketMessage.
     */
    @Test
    public void testGetTicket() {
    }

    /**
     * Test of prepareTicket method, of class NewSessionTicketMessage.
     */
    @Test
    public void testPrepareTicket() {
    }

    /**
     * Test of getTicketLength method, of class NewSessionTicketMessage.
     */
    @Test
    public void testGetTicketLength() {
    }

    /**
     * Test of setTicketLength method, of class NewSessionTicketMessage.
     */
    @Test
    public void testSetTicketLength_int() {
    }

    /**
     * Test of setTicketLength method, of class NewSessionTicketMessage.
     */
    @Test
    public void testSetTicketLength_ModifiableInteger() {
    }

    /**
     * Test of toString method, of class NewSessionTicketMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nNewSessionTicketMessage:");
        sb.append("\n  TicketLifeTimeHint: ").append("null");
        sb.append("\n  TicketLength: ").append("null");
        sb.append("\n  Ticket: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of toCompactString method, of class NewSessionTicketMessage.
     */
    @Test
    public void testToCompactString() {
    }

    /**
     * Test of getAllModifiableVariableHolders method, of class
     * NewSessionTicketMessage.
     */
    @Test
    public void testGetAllModifiableVariableHolders() {
    }

    /**
     * Test of getHandler method, of class NewSessionTicketMessage.
     */
    @Test
    public void testGetHandler() {
    }

}
