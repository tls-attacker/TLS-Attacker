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
import de.rub.nds.tlsattacker.tls.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.tls.protocol.parser.HelloVerifyRequestParserTest;
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
public class HelloVerifyRequestSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return HelloVerifyRequestParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    private byte[] protocolVersion;
    private byte cookieLength;
    private byte[] cookie;

    public HelloVerifyRequestSerializerTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, byte[] protocolVersion, byte cookieLength, byte[] cookie) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.protocolVersion = protocolVersion;
        this.cookieLength = cookieLength;
        this.cookie = cookie;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * HelloVerifyRequestSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        HelloVerifyRequestMessage msg = new HelloVerifyRequestMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setType(type.getValue());
        msg.setType(type.getValue());
        msg.setProtocolVersion(protocolVersion);
        msg.setCookieLength(cookieLength);
        msg.setCookie(cookie);
        HelloVerifyRequestSerializer serializer = new HelloVerifyRequestSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
