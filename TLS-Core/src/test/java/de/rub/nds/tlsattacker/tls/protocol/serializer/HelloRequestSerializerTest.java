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
import de.rub.nds.tlsattacker.tls.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.tls.protocol.parser.HelloRequestParserTest;
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
public class HelloRequestSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return HelloRequestParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    public HelloRequestSerializerTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * HelloRequestSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        HelloRequestMessage msg = new HelloRequestMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setLength(length);
        msg.setType(type.getValue());
        HelloRequestSerializer serializer = new HelloRequestSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
