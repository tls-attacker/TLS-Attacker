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
public class HeartbeatMessageTest {

    HeartbeatMessage message;

    @Before
    public void setUp() {
        message = new HeartbeatMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getHeartbeatMessageType method, of class HeartbeatMessage.
     */
    @Test
    public void testGetHeartbeatMessageType() {
    }

    /**
     * Test of setHeartbeatMessageType method, of class HeartbeatMessage.
     */
    @Test
    public void testSetHeartbeatMessageType_ModifiableByte() {
    }

    /**
     * Test of setHeartbeatMessageType method, of class HeartbeatMessage.
     */
    @Test
    public void testSetHeartbeatMessageType_byte() {
    }

    /**
     * Test of getPayloadLength method, of class HeartbeatMessage.
     */
    @Test
    public void testGetPayloadLength() {
    }

    /**
     * Test of setPayloadLength method, of class HeartbeatMessage.
     */
    @Test
    public void testSetPayloadLength_ModifiableInteger() {
    }

    /**
     * Test of setPayloadLength method, of class HeartbeatMessage.
     */
    @Test
    public void testSetPayloadLength_int() {
    }

    /**
     * Test of getPayload method, of class HeartbeatMessage.
     */
    @Test
    public void testGetPayload() {
    }

    /**
     * Test of setPayload method, of class HeartbeatMessage.
     */
    @Test
    public void testSetPayload_ModifiableByteArray() {
    }

    /**
     * Test of setPayload method, of class HeartbeatMessage.
     */
    @Test
    public void testSetPayload_byteArr() {
    }

    /**
     * Test of getPadding method, of class HeartbeatMessage.
     */
    @Test
    public void testGetPadding() {
    }

    /**
     * Test of setPadding method, of class HeartbeatMessage.
     */
    @Test
    public void testSetPadding_ModifiableByteArray() {
    }

    /**
     * Test of setPadding method, of class HeartbeatMessage.
     */
    @Test
    public void testSetPadding_byteArr() {
    }

    /**
     * Test of toString method, of class HeartbeatMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nHeartbeatMessage:");
        sb.append("\n  Type: ").append("null");
        sb.append("\n  Payload Length: ").append("null");
        sb.append("\n  Payload: ").append("null");
        sb.append("\n  Padding: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of toCompactString method, of class HeartbeatMessage.
     */
    @Test
    public void testToCompactString() {
    }

    /**
     * Test of getHandler method, of class HeartbeatMessage.
     */
    @Test
    public void testGetHandler() {
    }

}
