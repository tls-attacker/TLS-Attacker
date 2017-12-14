/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class CertificateMessageTest {
    CertificateMessage message;

    @Before
    public void setUp() {
        message = new CertificateMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class CertificateMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();

        sb.append("\nCertificateMessage:");
        sb.append("\n  Certificates Length: ").append("null");
        sb.append("\n  Certificate:\n").append("null");
        assertEquals(sb.toString(), message.toString());

        byte testBytes = 120;
        byte[] testArray = { 120 };

        sb.setLength(0);
        sb.append("\nCertificateMessage:");
        sb.append("\n  Certificates Length: ").append(testBytes);
        sb.append("\n  Certificate:\n").append(ArrayConverter.bytesToHexString(testArray));

        message.setCertificatesListLength(testBytes);
        message.setCertificatesListBytes(testArray);
        assertEquals(sb.toString(), message.toString());
    }
}
