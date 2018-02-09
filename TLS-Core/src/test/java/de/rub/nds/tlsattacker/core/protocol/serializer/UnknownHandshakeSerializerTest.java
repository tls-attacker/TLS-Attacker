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
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownHandshakeParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class UnknownHandshakeSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return UnknownHandshakeParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;
    private byte[] data;

    public UnknownHandshakeSerializerTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, byte[] data) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.data = data;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * UnknownHandshakeSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        UnknownHandshakeMessage msg = new UnknownHandshakeMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setType(type.getValue());
        msg.setLength(length);
        msg.setData(data);
        UnknownHandshakeSerializer serializer = new UnknownHandshakeSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
