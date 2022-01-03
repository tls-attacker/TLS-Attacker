/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CertificateStatusMessageTest {

    CertificateStatusMessage certificateStatusMessage;

    @Before
    public void setUp() {
        certificateStatusMessage = new CertificateStatusMessage();
    }

    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("CertificateStatusMessage:").append("\n null");

        String expectedString = sb.toString();
        Assert.assertEquals(expectedString, certificateStatusMessage.toString());
    }
}
