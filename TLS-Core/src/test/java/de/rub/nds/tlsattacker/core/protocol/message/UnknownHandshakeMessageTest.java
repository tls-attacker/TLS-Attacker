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
public class UnknownHandshakeMessageTest {

    UnknownHandshakeMessage message;

    @Before
    public void setUp() {
        message = new UnknownHandshakeMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getDataConfig method, of class UnknownHandshakeMessage.
     */
    @Test
    public void testGetDataConfig() {
    }

    /**
     * Test of setDataConfig method, of class UnknownHandshakeMessage.
     */
    @Test
    public void testSetDataConfig() {
    }

    /**
     * Test of getData method, of class UnknownHandshakeMessage.
     */
    @Test
    public void testGetData() {
    }

    /**
     * Test of setData method, of class UnknownHandshakeMessage.
     */
    @Test
    public void testSetData_ModifiableByteArray() {
    }

    /**
     * Test of setData method, of class UnknownHandshakeMessage.
     */
    @Test
    public void testSetData_byteArr() {
    }

    /**
     * Test of getHandler method, of class UnknownHandshakeMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of toString method, of class UnknownHandshakeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nUnknownHandshakeMessage:");
        sb.append("\n  Data: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
