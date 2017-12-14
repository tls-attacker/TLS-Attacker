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
public class ChangeCipherSpecMessageTest {
    ChangeCipherSpecMessage message;

    @Before
    public void setUp() {
        message = new ChangeCipherSpecMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getCcsProtocolType method, of class ChangeCipherSpecMessage.
     */
    @Test
    public void testGetCcsProtocolType() {
    }

    /**
     * Test of setCcsProtocolType method, of class ChangeCipherSpecMessage.
     */
    @Test
    public void testSetCcsProtocolType_ModifiableByte() {
    }

    /**
     * Test of setCcsProtocolType method, of class ChangeCipherSpecMessage.
     */
    @Test
    public void testSetCcsProtocolType_byte() {
    }

    /**
     * Test of toString method, of class ChangeCipherSpecMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nChangeCipherSpecMessage:");
        sb.append("\n  CCS ProtocolType: ").append("null");

        assertEquals(sb.toString(), message.toString());
    }

    /**
     * Test of toCompactString method, of class ChangeCipherSpecMessage.
     */
    @Test
    public void testToCompactString() {
    }

    /**
     * Test of getHandler method, of class ChangeCipherSpecMessage.
     */
    @Test
    public void testGetHandler() {
    }

}
