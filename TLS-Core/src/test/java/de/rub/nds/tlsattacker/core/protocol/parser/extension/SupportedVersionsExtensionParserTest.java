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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SupportedVersionsExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { {
                ArrayConverter.hexStringToByteArray("002B000D0C000203000301030203037F14"), 0,
                ArrayConverter.hexStringToByteArray("002B000D0C000203000301030203037F14"),
                ExtensionType.SUPPORTED_VERSIONS, 13, 12,
                ArrayConverter.hexStringToByteArray("000203000301030203037F14") } });
    }

    private final byte[] extension;
    private final int start;
    private final byte[] completeExtension;
    private final ExtensionType type;
    private final int extensionLength;
    private final int versionListLength;
    private final byte[] versionList;

    public SupportedVersionsExtensionParserTest(byte[] extension, int start, byte[] completeExtension,
            ExtensionType type, int extensionLength, int versionListLength, byte[] versionList) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.versionListLength = versionListLength;
        this.versionList = versionList;
    }

    /**
     * Test of parseExtensionMessageContent method, of class
     * SupportedVersionsExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        SupportedVersionsExtensionParser parser = new SupportedVersionsExtensionParser(start, extension);
        SupportedVersionsExtensionMessage msg = parser.parse();
        assertArrayEquals(msg.getExtensionBytes().getValue(), completeExtension);
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertTrue(extensionLength == msg.getExtensionLength().getValue());
        assertArrayEquals(msg.getSupportedVersions().getValue(), versionList);
        assertTrue(versionListLength == msg.getSupportedVersionsLength().getValue());
    }

}
