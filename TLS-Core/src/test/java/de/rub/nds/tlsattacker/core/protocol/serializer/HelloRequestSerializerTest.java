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
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRequestParserTest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class HelloRequestSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return HelloRequestParserTest.generateData();
    }

    private final byte[] message;

    public HelloRequestSerializerTest(byte[] message) {
        this.message = message;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class HelloRequestSerializer.
     */
    @Test
    public void testserializeProtocolMessageContent() {
        HelloRequestMessage msg = new HelloRequestMessage();
        HelloRequestSerializer serializer = new HelloRequestSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(message, serializer.serializeProtocolMessageContent());
    }

}
