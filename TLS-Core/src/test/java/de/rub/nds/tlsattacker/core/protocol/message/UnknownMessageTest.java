/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.config.Config;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;

public class UnknownMessageTest {

    UnknownMessage message;

    @Before
    public void setUp() {
        message = new UnknownMessage(Config.createConfig(), ProtocolMessageType.UNKNOWN);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class UnknownMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UnknownMessage:");
        sb.append("\n  Data: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
