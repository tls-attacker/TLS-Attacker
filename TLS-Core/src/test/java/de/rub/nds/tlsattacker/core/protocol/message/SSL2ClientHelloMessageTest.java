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

public class SSL2ClientHelloMessageTest {

    SSL2ClientHelloMessage message;

    @Before
    public void setUp() {
        message = new SSL2ClientHelloMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SSL2ClientHelloMessage:");
        sb.append("\n  Protocol Version: ").append("null");
        sb.append("\n  Type: ").append("null");
        sb.append("\n  Supported CipherSuites: ").append("null");
        sb.append("\n  Challange: ").append("null");
        sb.append("\n  SessionID: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
