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
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class DHClientKeyExchangeSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return DHClientKeyExchangeParserTest.generateData();
    }

    private final byte[] expectedPart;

    private final HandshakeMessageType type;
    private final int length;

    private final int serializedKeyLength;
    private final byte[] serializedKey;
    private final ProtocolVersion version;

    public DHClientKeyExchangeSerializerTest(byte[] message, HandshakeMessageType type, int length,
            int serializedKeyLength, byte[] serializedKey, ProtocolVersion version) {
        this.expectedPart = message;
        this.type = type;
        this.length = length;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.version = version;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * DHClientKeyExchangeSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        DHClientKeyExchangeMessage msg = new DHClientKeyExchangeMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setPublicKey(serializedKey);
        msg.setPublicKeyLength(serializedKeyLength);
        msg.setType(type.getValue());
        msg.setLength(length);
        DHClientKeyExchangeSerializer serializer = new DHClientKeyExchangeSerializer(msg, version);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
