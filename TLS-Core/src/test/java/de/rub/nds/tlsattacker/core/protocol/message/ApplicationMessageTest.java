/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ApplicationMessageTest {

    ApplicationMessage message;

    @Before
    public void setUp() {
        message = new ApplicationMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class ApplicationMessage.
     */
    @Test
    public void testToString() {

        StringBuilder sb = new StringBuilder();
        sb.append("ApplicationMessage:");
        sb.append("\n  Data: ").append("null");

        assertEquals(sb.toString(), message.toString());

        byte[] data = { 123 };
        message.setData(data);

        sb.setLength(0);
        sb.append("ApplicationMessage:");
        sb.append("\n  Data: ").append(ArrayConverter.bytesToHexString(data));

        assertEquals(sb.toString(), message.toString());
    }

}
