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
     * Test of toString method, of class HeartbeatMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HeartbeatMessage:");
        sb.append("\n  Type: ").append("null");
        sb.append("\n  Payload Length: ").append("null");
        sb.append("\n  Payload: ").append("null");
        sb.append("\n  Padding: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
