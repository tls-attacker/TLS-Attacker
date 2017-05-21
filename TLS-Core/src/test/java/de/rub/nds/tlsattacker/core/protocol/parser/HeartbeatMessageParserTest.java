/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.util.ByteRepresentationConverter;
import java.util.Arrays;
import java.util.Collection;
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
    private static String heartbeatRequest = "010012000075a6d1d422693ea31584902266171b14ee376d595f5c65aeba8d04b0378faeda";
    private static String requestPayload = "000075a6d1d422693ea31584902266171b14";
    private static String requestPadding = "ee376d595f5c65aeba8d04b0378faeda";
    private static String heartbeatResponse = "020012000075a6d1d422693ea31584902266171b1429ee15bbaa07f19c012dc29e2449e1e1";
    private static String responsePayload = requestPayload;
    private static String responsePadding = "29ee15bbaa07f19c012dc29e2449e1e1";

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { ByteRepresentationConverter.hexStringToByteArray(heartbeatRequest), 0,
                        ByteRepresentationConverter.hexStringToByteArray(heartbeatRequest), (byte) 0x1, 18,
                        ByteRepresentationConverter.hexStringToByteArray(requestPayload),
                        ByteRepresentationConverter.hexStringToByteArray(requestPadding) },
                { ByteRepresentationConverter.hexStringToByteArray(heartbeatResponse), 0,
                        ByteRepresentationConverter.hexStringToByteArray(heartbeatResponse), (byte) 0x2, 18,
                        ByteRepresentationConverter.hexStringToByteArray(responsePayload),
                        ByteRepresentationConverter.hexStringToByteArray(responsePadding) } });
    }

    private final byte[] message;
    private final int start;
    private final byte[] expectedPart;

    private final byte heartBeatType;
    private final int payloadLength;
    private final byte[] payload;
    private final byte[] padding;

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
        HeartbeatMessageParser parser = new HeartbeatMessageParser(start, message, ProtocolVersion.TLS12);
        HeartbeatMessage msg = parser.parse();
        assertTrue(heartBeatType == msg.getHeartbeatMessageType().getValue());
        assertTrue(payloadLength == msg.getPayloadLength().getValue());
        assertArrayEquals(payload, msg.getPayload().getValue());
        assertArrayEquals(padding, msg.getPadding().getValue());
    }
}
