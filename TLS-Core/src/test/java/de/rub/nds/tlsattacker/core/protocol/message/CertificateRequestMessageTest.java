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

public class CertificateRequestMessageTest {
    CertificateRequestMessage message;

    @Before
    public void setUp() {
        message = new CertificateRequestMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class CertificateRequestMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("CertificateRequestMessage:");
        sb.append("\n  Certificate Types Count: ").append("null");
        sb.append("\n  Certificate Types: ").append("null");
        sb.append("\n  Signature Hash Algorithms Length: ").append("null");
        sb.append("\n  Signature Hash Algorithms: ").append("null");
        sb.append("\n  Distinguished Names Length: ").append("null");
        assertEquals(message.toString(), sb.toString());
    }

}
