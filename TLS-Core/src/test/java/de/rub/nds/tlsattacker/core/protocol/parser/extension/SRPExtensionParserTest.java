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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SRPExtensionParserTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ExtensionType.SRP,
                new byte[] { 0x00, 0x0C, 0x00, 0x05, 0x04, 0x01, 0x02, 0x03, 0x04 }, 5, 0, 4,
                ArrayConverter.hexStringToByteArray("01020304") } });
    }

    private final ExtensionType extensionType;
    private final byte[] extensionBytes;
    private final int extensionLength;
    private final int startParsing;
    private final int srpIdentifierLength;
    private final byte[] srpIdentifier;
    private SRPExtensionParser parser;
    private SRPExtensionMessage message;

    public SRPExtensionParserTest(ExtensionType extensionType, byte[] extensionBytes, int extensionLength,
            int startParsing, int srpIdentifierLength, byte[] srpIdentifier) {
        this.extensionType = extensionType;
        this.extensionBytes = extensionBytes;
        this.extensionLength = extensionLength;
        this.startParsing = startParsing;
        this.srpIdentifierLength = srpIdentifierLength;
        this.srpIdentifier = srpIdentifier;
    }

    @Before
    public void setUp() {
        parser = new SRPExtensionParser(startParsing, extensionBytes);

    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();

        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());

        assertEquals(srpIdentifierLength, (long) message.getSrpIdentifierLength().getValue());
        assertArrayEquals(srpIdentifier, message.getSrpIdentifier().getValue());

    }

}
