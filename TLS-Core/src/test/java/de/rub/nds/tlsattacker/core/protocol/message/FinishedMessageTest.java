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
public class FinishedMessageTest {

    FinishedMessage message;

    @Before
    public void setUp() {
        message = new FinishedMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getVerifyData method, of class FinishedMessage.
     */
    @Test
    public void testGetVerifyData() {
    }

    /**
     * Test of setVerifyData method, of class FinishedMessage.
     */
    @Test
    public void testSetVerifyData_ModifiableByteArray() {
    }

    /**
     * Test of setVerifyData method, of class FinishedMessage.
     */
    @Test
    public void testSetVerifyData_byteArr() {
    }

    /**
     * Test of toString method, of class FinishedMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nFinishedMessage:");
        sb.append("\n  Verify Data: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getHandler method, of class FinishedMessage.
     */
    @Test
    public void testGetHandler() {
    }

}
