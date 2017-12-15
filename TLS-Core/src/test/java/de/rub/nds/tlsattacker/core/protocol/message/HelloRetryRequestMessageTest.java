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
public class HelloRetryRequestMessageTest {

    HelloRetryRequestMessage message;

    @Before
    public void setUp() {
        message = new HelloRetryRequestMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getProtocolVersion method, of class HelloRetryRequestMessage.
     */
    @Test
    public void testGetProtocolVersion() {
    }

    /**
     * Test of setProtocolVersion method, of class HelloRetryRequestMessage.
     */
    @Test
    public void testSetProtocolVersion_ModifiableByteArray() {
    }

    /**
     * Test of setProtocolVersion method, of class HelloRetryRequestMessage.
     */
    @Test
    public void testSetProtocolVersion_byteArr() {
    }

    /**
     * Test of getSelectedCipherSuite method, of class HelloRetryRequestMessage.
     */
    @Test
    public void testGetSelectedCipherSuite() {
    }

    /**
     * Test of setSelectedCipherSuite method, of class HelloRetryRequestMessage.
     */
    @Test
    public void testSetSelectedCipherSuite_ModifiableByteArray() {
    }

    /**
     * Test of setSelectedCipherSuite method, of class HelloRetryRequestMessage.
     */
    @Test
    public void testSetSelectedCipherSuite_byteArr() {
    }

    /**
     * Test of toString method, of class HelloRetryRequestMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nHelloRetryRequestMessage:");
        sb.append("\n  Protocol Version: ").append("null");
        sb.append("\n  Selected Cipher Suite: ").append("null");
        sb.append("\n  Extensions: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getHandler method, of class HelloRetryRequestMessage.
     */
    @Test
    public void testGetHandler() {
    }

}
