/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class AlertMessageTest {

    private AlertMessage message;

    @Before
    public void setUp() {
        message = new AlertMessage();
    }

    @Test
    public void testToString() {
        byte testBytes = 120;
        StringBuilder sb = new StringBuilder();
        sb.append("AlertMessage:").append("\nALERT message:\n  Level: ").append(testBytes).append("\n  Description: ")
                .append(testBytes);

        message.setDescription(testBytes);
        message.setLevel(testBytes);
        assertEquals(sb.toString(), message.toString());
    }

}
