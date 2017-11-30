/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HeartbeatMessageParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HeartbeatMessageSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return HeartbeatMessageParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private byte heartBeatType;
    private int payloadLength;
    private byte[] payload;
    private byte[] padding;

    public HeartbeatMessageSerializerTest(byte[] message, int start, byte[] expectedPart, byte heartBeatType,
            int payloadLength, byte[] payload, byte[] padding) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.heartBeatType = heartBeatType;
        this.payloadLength = payloadLength;
        this.payload = payload;
        this.padding = padding;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class
     * HeartbeatMessageSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        HeartbeatMessage msg = new HeartbeatMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setHeartbeatMessageType(heartBeatType);
        msg.setPayloadLength(payloadLength);
        msg.setPayload(payload);
        msg.setPadding(padding);
        HeartbeatMessageSerializer serializer = new HeartbeatMessageSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
