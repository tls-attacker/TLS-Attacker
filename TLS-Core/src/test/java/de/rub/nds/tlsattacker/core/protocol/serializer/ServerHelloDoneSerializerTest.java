/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

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
    private ProtocolVersion version;

    public ServerHelloDoneSerializerTest(byte[] message, ProtocolVersion version) {
        this.message = message;
        this.version = version;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class ServerHelloDoneSerializer.
     */
    @Test
    public void testserializeProtocolMessageContent() {
        ServerHelloDoneMessage msg = new ServerHelloDoneMessage();
        ServerHelloDoneSerializer serializer = new ServerHelloDoneSerializer(msg, version);
        assertArrayEquals(message, serializer.serializeProtocolMessageContent());
    }

}
