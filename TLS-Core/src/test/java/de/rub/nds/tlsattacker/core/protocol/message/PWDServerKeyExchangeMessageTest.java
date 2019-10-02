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

public class PWDServerKeyExchangeMessageTest {

    @Test
    public void testToString() {
        PWDServerKeyExchangeMessage message = new PWDServerKeyExchangeMessage();
        StringBuilder sb = new StringBuilder();
        sb.append("PWDServerKeyExchangeMessage:");
        sb.append("\n  Salt: ");
        sb.append("null");
        sb.append("\n  Curve Type: ");
        sb.append("null");
        sb.append("\n  Named Curve: ");
        sb.append("null");
        sb.append("\n  Element: ");
        sb.append("null");
        sb.append("\n  Scalar: ");
        sb.append("null");

        assertEquals(sb.toString(), message.toString());
    }

}