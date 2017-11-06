/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *

 */
@RunWith(Parameterized.class)
public class HelloVerifyRequestParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("030000170000000000000017feff1415520276466763250a851c5b9eaeb44676ff3381"),
                        HandshakeMessageType.HELLO_VERIFY_REQUEST, 23, ProtocolVersion.DTLS10.getValue(), (byte) 20,
                        ArrayConverter.hexStringToByteArray("15520276466763250a851c5b9eaeb44676ff3381"), 0, 23, 0 } });
    }

    private final byte[] message;

    private final HandshakeMessageType type;
    private final int length;

    private final byte[] protocolVersion;
    private final byte cookieLength;
    private final byte[] cookie;

    private final int fragmentOffset;
    private final int fragmentLength;
    private final int messageSeq;

    public HelloVerifyRequestParserTest(byte[] message, HandshakeMessageType type, int length, byte[] protocolVersion,
            byte cookieLength, byte[] cookie, int fragmentOffset, int fragmentLength, int messageSeq) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.protocolVersion = protocolVersion;
        this.cookieLength = cookieLength;
        this.cookie = cookie;
        this.fragmentLength = fragmentLength;
        this.fragmentOffset = fragmentOffset;
        this.messageSeq = messageSeq;
    }

    /**
     * Test of parse method, of class HelloVerifyRequestParser.
     */
    @Test
    public void testParse() {
        HelloVerifyRequestParser parser = new HelloVerifyRequestParser(0, message, ProtocolVersion.DTLS10);
        HelloVerifyRequestMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertArrayEquals(protocolVersion, msg.getProtocolVersion().getValue());
        assertArrayEquals(cookie, msg.getCookie().getValue());
        assertTrue(cookieLength == msg.getCookieLength().getValue());
        assertTrue(messageSeq == msg.getMessageSeq().getValue());
        assertTrue(fragmentLength == msg.getFragmentLength().getValue());
        assertTrue(fragmentOffset == msg.getFragmentOffset().getValue());
    }
}
