/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownHandshakeParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class UnknownHandshakeSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return UnknownHandshakeParserTest.generateData();
    }

    private byte[] message;

    public UnknownHandshakeSerializerTest(byte[] message) {
        this.message = message;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class UnknownHandshakeSerializer.
     */
    @Test
    public void testserializeProtocolMessageContent() {
        UnknownHandshakeMessage msg = new UnknownHandshakeMessage();
        msg.setData(message);
        UnknownHandshakeSerializer serializer = new UnknownHandshakeSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(message, serializer.serializeProtocolMessageContent());
    }

}
