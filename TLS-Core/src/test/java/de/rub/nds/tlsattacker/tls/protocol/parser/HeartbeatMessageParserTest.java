/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.HeartbeatMessage;
import java.util.Arrays;
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
public class HeartbeatMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {});
    }

    // TODO get a real heartbeat message

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private byte heartBeatType;
    private int payloadLength;
    private byte[] payload;
    private byte[] padding;

    public HeartbeatMessageParserTest(byte[] message, int start, byte[] expectedPart, byte heartBeatType,
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
     * Test of parse method, of class HeartbeatMessageParser.
     */
    @Test
    public void testParse() {
        HeartbeatMessageParser parser = new HeartbeatMessageParser(start, message);
        HeartbeatMessage msg = parser.parse();
        assertTrue(heartBeatType == msg.getHeartbeatMessageType().getValue());
        assertTrue(payloadLength == msg.getPayloadLength().getValue());
        assertArrayEquals(payload, msg.getPayload().getValue());
        assertArrayEquals(padding, msg.getPadding().getValue());
    }

}
