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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PaddingExtensionParserTest {

    /**
     * Parameterized set up of the test vector.
     *
     * @return test vector (extensionType, extensionLength, extensionPayload,
     *         expectedBytes)
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ExtensionType.PADDING, 6, new byte[] { 0, 0, 0, 0, 0, 0 },
                ArrayConverter.hexStringToByteArray("00150006000000000000"), 0 } });
    }

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] extensionPayload;
    private final byte[] expectedBytes;
    private final int startParsing;
    private PaddingExtensionParser parser;
    private PaddingExtensionMessage message;

    public PaddingExtensionParserTest(ExtensionType extensionType, int extensionLength, byte[] extensionPayload,
            byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.extensionPayload = extensionPayload;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Before
    public void setUp() {
        parser = new PaddingExtensionParser(startParsing, expectedBytes);
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();

        assertArrayEquals(ExtensionType.PADDING.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
        assertArrayEquals(extensionPayload, message.getPaddingBytes().getValue());
    }

}
