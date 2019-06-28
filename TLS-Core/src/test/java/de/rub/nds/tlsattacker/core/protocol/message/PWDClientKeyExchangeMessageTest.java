/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import static org.junit.Assert.*;
import org.junit.Test;

public class PWDClientKeyExchangeMessageTest {

    @Test
    public void testToString() {
        PWDClientKeyExchangeMessage message = new PWDClientKeyExchangeMessage();
        StringBuilder sb = new StringBuilder();
        sb.append("PWDClientKeyExchangeMessage:");
        sb.append("\n  Element: ");
        sb.append("null");
        sb.append("\n  Scalar: ");
        sb.append("null");

        assertEquals(sb.toString(), message.toString());
    }

}