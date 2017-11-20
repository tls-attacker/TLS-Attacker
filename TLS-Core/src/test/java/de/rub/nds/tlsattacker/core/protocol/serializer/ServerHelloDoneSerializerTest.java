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
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloDoneParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

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
    private ProtocolVersion version;

    public ServerHelloDoneSerializerTest(byte[] message, HandshakeMessageType type, int length, ProtocolVersion version) {
        this.message = message;
        this.start = 0;
        this.expectedPart = message;
        this.type = type;
        this.length = length;
        this.version = version;
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
        ServerHelloDoneSerializer serializer = new ServerHelloDoneSerializer(msg, version);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
