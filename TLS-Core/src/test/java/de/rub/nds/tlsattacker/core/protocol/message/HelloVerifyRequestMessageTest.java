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

public class HelloVerifyRequestMessageTest {

    HelloVerifyRequestMessage message;

    @Before
    public void setUp() {
        message = new HelloVerifyRequestMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HelloVerifyRequestMessage:");
        sb.append("\n  ProtocolVersion: ").append("null");
        sb.append("\n  Cookie Length: ").append("null");
        sb.append("\n  Cookie: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
