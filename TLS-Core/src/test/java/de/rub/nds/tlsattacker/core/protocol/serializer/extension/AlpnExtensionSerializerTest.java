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
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.AlpnExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class AlpnExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return AlpnExtensionParserTest.generateData();
    }

    private final ExtensionType extensionType;
    private final byte[] expectedBytes;
    private final int extensionLength;
    private final int startParsing;
    private final int alpnExtensionLength;
    private final byte[] alpnAnnouncedProtocols;
    private AlpnExtensionSerializer serializer;
    private AlpnExtensionMessage message;

    public AlpnExtensionSerializerTest(ExtensionType extensionType, byte[] expectedBytes, int extensionLength,
            int startParsing, int alpnExtensionLength, byte[] alpnAnnouncedProtocols) {
        this.extensionType = extensionType;
        this.expectedBytes = expectedBytes;
        this.extensionLength = extensionLength;
        this.startParsing = startParsing;
        this.alpnExtensionLength = alpnExtensionLength;
        this.alpnAnnouncedProtocols = alpnAnnouncedProtocols;
    }

    @Before
    public void setUp() {
        message = new AlpnExtensionMessage();
        serializer = new AlpnExtensionSerializer(message);
    }

    @Test
    public void testSerializeExtensionContent() {
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);
        message.setAlpnExtensionLength(alpnExtensionLength);
        message.setAlpnAnnouncedProtocols(alpnAnnouncedProtocols);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }

}
