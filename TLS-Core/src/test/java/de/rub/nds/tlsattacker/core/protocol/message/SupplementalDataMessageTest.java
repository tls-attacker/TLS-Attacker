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
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class SupplementalDataMessageTest {

    SupplementalDataMessage message;

    @Before
    public void setUp() {
        message = new SupplementalDataMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class SupplementalDataMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SupplementalDataMessage:");
        sb.append("\n  Supplemental Data Length: ").append("null");
        sb.append("\n  SupplementalDataEntries:\n").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
