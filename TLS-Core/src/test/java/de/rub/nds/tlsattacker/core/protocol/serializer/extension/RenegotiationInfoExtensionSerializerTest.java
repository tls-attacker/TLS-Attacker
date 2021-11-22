/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RenegotiationInfoExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class RenegotiationInfoExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return RenegotiationInfoExtensionParserTest.generateData();
    }

    private final int extensionPayloadLength;
    private final byte[] extensionPayload;
    private final byte[] expectedBytes;

    public RenegotiationInfoExtensionSerializerTest(int extensionPayloadLength, byte[] extensionPayload,
        byte[] expectedBytes) {
        this.extensionPayload = extensionPayload;
        this.expectedBytes = expectedBytes;
        this.extensionPayloadLength = extensionPayloadLength;
    }

    @Test
    public void testSerializeExtensionContent() {
        RenegotiationInfoExtensionMessage message = new RenegotiationInfoExtensionMessage();
        message.setRenegotiationInfo(extensionPayload);
        message.setRenegotiationInfoLength(extensionPayloadLength);
        RenegotiationInfoExtensionSerializer serializer = new RenegotiationInfoExtensionSerializer(message);

        assertArrayEquals(expectedBytes, serializer.serializeExtensionContent());
    }
}
