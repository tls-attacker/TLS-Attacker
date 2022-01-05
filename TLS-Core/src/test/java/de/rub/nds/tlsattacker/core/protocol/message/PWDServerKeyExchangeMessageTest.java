/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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