/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ServerHelloDoneParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ServerHelloDoneParserTest;
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
public class ServerHelloDoneSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ServerHelloDoneParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    public ServerHelloDoneSerializerTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * ServerHelloDoneSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        ServerHelloDoneMessage msg = new ServerHelloDoneMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setType(type.getValue());
        msg.setLength(length);
        ServerHelloDoneSerializer serializer = new ServerHelloDoneSerializer(msg);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
