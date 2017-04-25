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
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
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
public class FinishedMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {}); // TODO add testcases!!
    }

    private final byte[] message;
    private final int start;
    private final byte[] expectedPart;

    private final HandshakeMessageType type;
    private final int length;

    private final byte[] verifyData;

    public FinishedMessageParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, byte[] verifyData) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.verifyData = verifyData;
    }

    /**
     * Test of parse method, of class FinishedMessageParser.
     */
    @Test
    public void testParse() {
        FinishedMessageParser parser = new FinishedMessageParser(start, message, ProtocolVersion.TLS12);
        FinishedMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertArrayEquals(verifyData, msg.getVerifyData().getValue());
    }
}
