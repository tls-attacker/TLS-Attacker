/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateMessageParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateMessageSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return CertificateMessageParserTest.generateData();
    }

    private byte[] expectedPart;
    private int certificatesLength;
    private byte[] certificateBytes;
    private ProtocolVersion version;

    public CertificateMessageSerializerTest(byte[] message, int certificatesLength, byte[] certificateBytes,
        ProtocolVersion version) {
        this.expectedPart = message;
        this.certificatesLength = certificatesLength;
        this.certificateBytes = certificateBytes;
        this.version = version;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class CertificateMessageSerializer.
     */
    @Test
    public void testserializeProtocolMessageContent() {
        CertificateMessage message = new CertificateMessage();
        message.setCertificatesListLength(certificatesLength);
        message.setCertificatesListBytes(certificateBytes);
        CertificateMessageSerializer serializer = new CertificateMessageSerializer(message, version);
        assertArrayEquals(expectedPart, serializer.serializeProtocolMessageContent());
    }
}
