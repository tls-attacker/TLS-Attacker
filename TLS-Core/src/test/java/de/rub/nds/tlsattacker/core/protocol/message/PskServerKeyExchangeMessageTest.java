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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class PskServerKeyExchangeMessageTest {

    PskServerKeyExchangeMessage message;

    @Before
    public void setUp() {
        message = new PskServerKeyExchangeMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class PskServerKeyExchangeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskServerKeyExchangeMessage:");
        sb.append("\n  IdentityHintLength: ").append("null");
        sb.append("\n  IdentityHint: ").append("null");

        Assert.assertEquals(message.toString(), sb.toString());
    }

}
