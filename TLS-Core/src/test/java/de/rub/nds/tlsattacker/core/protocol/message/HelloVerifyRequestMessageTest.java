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
