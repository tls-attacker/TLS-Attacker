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
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedMessageParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class FinishedSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return FinishedMessageParserTest.generateData();
    }

    private final byte[] expectedPart;

    private final HandshakeMessageType type;
    private final int length;

    private final byte[] verifyData;

    private final ProtocolVersion version;

    public FinishedSerializerTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, byte[] verifyData, ProtocolVersion version) {
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.verifyData = verifyData;
        this.version = version;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * FinishedSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        FinishedMessage msg = new FinishedMessage();
        msg.setLength(length);
        msg.setType(type.getValue());
        msg.setVerifyData(verifyData);
        msg.setCompleteResultingMessage(expectedPart);
        FinishedSerializer serializer = new FinishedSerializer(msg, version);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
