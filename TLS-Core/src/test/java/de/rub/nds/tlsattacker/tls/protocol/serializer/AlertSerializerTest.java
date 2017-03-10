/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.AlertParserTest;
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
public class AlertSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return AlertParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;
    private byte level;
    private byte description;

    public AlertSerializerTest(byte[] message, int start, byte[] expectedPart, byte level, byte description) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.level = level;
        this.description = description;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class AlertSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        AlertMessage message = new AlertMessage();
        message.setLevel(level);
        message.setDescription(description);
        message.setCompleteResultingMessage(expectedPart);
        AlertSerializer serializer = new AlertSerializer(message);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
