/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRequestParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HelloRequestSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return HelloRequestParserTest.generateData();
    }

    private final byte[] message;
    private final int start;
    private final byte[] expectedPart;

    private final HandshakeMessageType type;
    private final int length;

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
