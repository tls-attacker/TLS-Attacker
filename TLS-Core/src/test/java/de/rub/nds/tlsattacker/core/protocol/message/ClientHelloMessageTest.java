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
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ClientHelloMessageTest {

    ClientHelloMessage message;

    @Before
    public void setUp() {
        message = new ClientHelloMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class ClientHelloMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ClientHelloMessage:");
        sb.append("\n  Protocol Version: ").append("null");
        sb.append("\n  Client Unix Time: ").append("null");
        sb.append("\n  Client Random: ").append("null");
        sb.append("\n  Session ID: ").append("null");
        sb.append("\n  Supported Cipher Suites: ").append("null");
        sb.append("\n  Supported Compression Methods: ").append("null");
        sb.append("\n  Extensions: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }
}
