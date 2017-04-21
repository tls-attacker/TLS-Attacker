/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParserTest;
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
public class ECDHClientKeyExchangeSerializerTest {

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    private int serializedKeyLength;
    private byte[] serializedKey;

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ECDHClientKeyExchangeParserTest.generateData();
    }

    public ECDHClientKeyExchangeSerializerTest(byte[] message, int start, byte[] expectedPart,
            HandshakeMessageType type, int length, int serializedKeyLength, byte[] serializedKey) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * ECDHClientKeyExchangeSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        ECDHClientKeyExchangeMessage msg = new ECDHClientKeyExchangeMessage();
        msg.setLength(length);
        msg.setType(type.getValue());
        msg.setSerializedPublicKey(serializedKey);
        msg.setSerializedPublicKeyLength(serializedKeyLength);
        msg.setCompleteResultingMessage(expectedPart);
        ECDHClientKeyExchangeSerializer serializer = new ECDHClientKeyExchangeSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
