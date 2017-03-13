/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.tls.protocol.parser.ApplicationMessageParserTest;
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
public class ApplicationMessageSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ApplicationMessageParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;
    private byte[] data;

    public ApplicationMessageSerializerTest(byte[] message, int start, byte[] expectedPart, byte[] data) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.data = data;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class
     * ApplicationMessageSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        ApplicationMessage message = new ApplicationMessage();
        message.setData(data);
        message.setCompleteResultingMessage(expectedPart);
        ApplicationMessageSerializer serializer = new ApplicationMessageSerializer(message, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
