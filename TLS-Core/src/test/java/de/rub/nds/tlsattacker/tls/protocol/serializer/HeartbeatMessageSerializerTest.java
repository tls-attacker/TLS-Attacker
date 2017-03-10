/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.tls.protocol.parser.HeartbeatMessageParserTest;
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
public class HeartbeatMessageSerializerTest {

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private byte heartBeatType;
    private int payloadLength;
    private byte[] payload;
    private byte[] padding;

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return HeartbeatMessageParserTest.generateData();
    }

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
        HeartbeatMessageSerializer serializer = new HeartbeatMessageSerializer(msg);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
