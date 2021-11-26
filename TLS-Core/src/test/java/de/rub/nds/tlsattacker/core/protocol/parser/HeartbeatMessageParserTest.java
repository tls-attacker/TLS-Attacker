/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HeartbeatMessageParserTest {

    private static byte[] heartbeatRequest = ArrayConverter
        .hexStringToByteArray("010012000075a6d1d422693ea31584902266171b14ee376d595f5c65aeba8d04b0378faeda");
    private static byte[] requestPayload = ArrayConverter.hexStringToByteArray("000075a6d1d422693ea31584902266171b14");
    private static byte[] requestPadding = ArrayConverter.hexStringToByteArray("ee376d595f5c65aeba8d04b0378faeda");
    private static byte[] heartbeatResponse = ArrayConverter
        .hexStringToByteArray("020012000075a6d1d422693ea31584902266171b1429ee15bbaa07f19c012dc29e2449e1e1");
    private static byte[] responsePayload = requestPayload;
    private static byte[] responsePadding = ArrayConverter.hexStringToByteArray("29ee15bbaa07f19c012dc29e2449e1e1");

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { heartbeatRequest, (byte) 0x1, 18, requestPayload, requestPadding },
            { heartbeatResponse, (byte) 0x2, 18, responsePayload, responsePadding } });
    }

    private final byte[] message;
    // private final byte[] expectedPart;

    private final byte heartBeatType;
    private final int payloadLength;
    private final byte[] payload;
    private final byte[] padding;
    private final Config config = Config.createConfig();

    public HeartbeatMessageParserTest(byte[] message, byte heartBeatType, int payloadLength, byte[] payload,
        byte[] padding) {
        this.message = message;
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
        HeartbeatMessageParser parser =
            new HeartbeatMessageParser(new ByteArrayInputStream(message), ProtocolVersion.TLS12, config);
        HeartbeatMessage msg = new HeartbeatMessage();
        parser.parse(msg);
        assertTrue(heartBeatType == msg.getHeartbeatMessageType().getValue());
        assertTrue(payloadLength == msg.getPayloadLength().getValue());
        assertArrayEquals(payload, msg.getPayload().getValue());
        assertArrayEquals(padding, msg.getPadding().getValue());
    }
}
