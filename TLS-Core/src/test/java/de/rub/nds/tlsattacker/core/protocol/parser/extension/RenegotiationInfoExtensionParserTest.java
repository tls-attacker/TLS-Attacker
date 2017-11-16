/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class RenegotiationInfoExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ExtensionType.RENEGOTIATION_INFO, 1, 0, new byte[] {},
                ArrayConverter.hexStringToByteArray("ff01000100"), 0 } });
    }

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final int extensionPayloadLength;
    private final byte[] extensionPayload;
    private final byte[] expectedBytes;
    private final int startParsing;
    private RenegotiationInfoExtensionParser parser;
    private RenegotiationInfoExtensionMessage message;

    public RenegotiationInfoExtensionParserTest(ExtensionType extensionType, int extensionLength,
            int extensionPayloadLength, byte[] extensionPayload, byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.extensionPayload = extensionPayload;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
        this.extensionPayloadLength = extensionPayloadLength;
    }

    @Before
    public void setUp() {
        parser = new RenegotiationInfoExtensionParser(startParsing, expectedBytes);
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();

        assertEquals(extensionType, message.getExtensionTypeConstant());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
        assertEquals(extensionPayloadLength, (long) message.getRenegotiationInfoLength().getValue());
        assertArrayEquals(extensionPayload, message.getRenegotiationInfo().getValue());
    }

}
