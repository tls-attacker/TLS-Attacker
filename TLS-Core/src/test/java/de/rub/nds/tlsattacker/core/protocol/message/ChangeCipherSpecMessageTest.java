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
     * Test of toString method, of class ChangeCipherSpecMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ChangeCipherSpecMessage:");
        sb.append("\n  CCS ProtocolType: ").append("null");

        assertEquals(sb.toString(), message.toString());
    }
}
