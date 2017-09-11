/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Pierre Tilhaus
 */
public class AlertMessageTest {

    private AlertMessage message;

    @Before
    public void setUp() {
        message = new AlertMessage();
    }

    public void testToString() {
        byte testBytes = 120;
        StringBuilder sb = new StringBuilder(AlertMessage.class.toString());
        sb.append("\nALERT message:\n  Level: 120\n  Description: 120");

        message.setDescription(testBytes);
        message.setLevel(testBytes);
        assertEquals(sb, message.toString());
    }

}
