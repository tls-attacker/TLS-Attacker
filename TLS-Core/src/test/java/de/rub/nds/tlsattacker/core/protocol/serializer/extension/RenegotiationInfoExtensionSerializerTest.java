/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RenegotiationInfoExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class RenegotiationInfoExtensionSerializerTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] extensionPayload;
    private final byte[] expectedBytes;
    private final int startParsing;
    private RenegotiationInfoExtensionMessage message;

    public RenegotiationInfoExtensionSerializerTest(ExtensionType extensionType, int extensionLength,
            byte[] extensionPayload, byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.extensionPayload = extensionPayload;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return RenegotiationInfoExtensionParserTest.generateData();
    }

    @Test
    public void testSerializeExtensionContent() {
        message = new RenegotiationInfoExtensionMessage();
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);
        message.setRenegotiationInfo(extensionPayload);

        RenegotiationInfoExtensionSerializer serializer = new RenegotiationInfoExtensionSerializer(message);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
