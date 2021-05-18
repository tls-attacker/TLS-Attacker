/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

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
     * Test of toString method, of class HelloRetryRequestMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HelloRetryRequestMessage:");
        sb.append("\n  Protocol Version: ").append("null");
        sb.append("\n  Selected Cipher Suite: ").append("null");
        sb.append("\n  Extensions: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
