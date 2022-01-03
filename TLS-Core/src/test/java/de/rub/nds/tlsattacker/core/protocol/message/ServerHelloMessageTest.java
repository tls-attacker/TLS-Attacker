/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ServerHelloMessageTest {

    ServerHelloMessage message;

    @Before
    public void setUp() {
        message = new ServerHelloMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class ServerHelloMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HandshakeMessage:");
        sb.append("\n  Type: ").append("null");
        sb.append("\n  Length: ").append("null");
        sb.append("\n  Protocol Version: ").append("null");
        sb.append("\n  Server Unix Time: ").append("null");
        sb.append("\n  Server Random: ").append("null");
        sb.append("\n  Session ID: ").append("null");
        sb.append("\n  Selected Cipher Suite: ").append("null");
        sb.append("\n  Selected Compression Method: ").append("null");
        sb.append("\n  Extensions: ").append("null");

        assertEquals(sb.toString(), message.toString());
    }

}
