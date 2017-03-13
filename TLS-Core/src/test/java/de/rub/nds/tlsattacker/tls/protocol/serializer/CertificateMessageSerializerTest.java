/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.tls.protocol.parser.CertificateMessageParserTest;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class CertificateMessageSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return CertificateMessageParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    private int certificatesLength;
    private byte[] certificateBytes;

    public CertificateMessageSerializerTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, int certificatesLength, byte[] certificateBytes) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.certificatesLength = certificatesLength;
        this.certificateBytes = certificateBytes;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * CertificateMessageSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        CertificateMessage message = new CertificateMessage();
        message.setCertificatesLength(certificatesLength);
        message.setX509CertificateBytes(certificateBytes);
        message.setLength(length);
        message.setType(type.getValue());
        CertificateMessageSerializer serializer = new CertificateMessageSerializer(message, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }
}
