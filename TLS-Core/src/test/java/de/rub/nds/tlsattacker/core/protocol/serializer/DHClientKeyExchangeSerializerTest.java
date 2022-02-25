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
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
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
    private final int serializedKeyLength;
    private final byte[] serializedKey;

    public DHClientKeyExchangeSerializerTest(byte[] message, int serializedKeyLength, byte[] serializedKey,
        ProtocolVersion version) {
        this.expectedPart = message;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class DHClientKeyExchangeSerializer.
     */
    @Test
    public void testserializeProtocolMessageContent() {
        DHClientKeyExchangeMessage msg = new DHClientKeyExchangeMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setPublicKey(serializedKey);
        msg.setPublicKeyLength(serializedKeyLength);
        DHClientKeyExchangeSerializer serializer = new DHClientKeyExchangeSerializer(msg);
        assertArrayEquals(expectedPart, serializer.serializeProtocolMessageContent());
    }

}
