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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECPointFormatExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("000b000403000102"), 0,
                ArrayConverter.hexStringToByteArray("000b000403000102"), ExtensionType.EC_POINT_FORMATS, 4, 3,
                new byte[] { 0, 1, 2 } } }); // is the same for TLS10 and TLS11
    }

    private byte[] extension;
    private int start;
    private byte[] completeExtension;
    private ExtensionType type;
    private int extensionLength;
    private int pointFormatLength;
    private byte[] pointFormats;

    public ECPointFormatExtensionParserTest(byte[] extension, int start, byte[] completeExtension, ExtensionType type,
            int extensionLength, int pointFormatLength, byte[] pointFormats) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.pointFormatLength = pointFormatLength;
        this.pointFormats = pointFormats;
    }

    /**
     * Test of parseExtensionMessageContent method, of class
     * ECPointFormatExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        ECPointFormatExtensionParser parser = new ECPointFormatExtensionParser(start, extension);
        ECPointFormatExtensionMessage msg = parser.parse();
        assertArrayEquals(msg.getExtensionBytes().getValue(), completeExtension);
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertTrue(extensionLength == msg.getExtensionLength().getValue());
        assertArrayEquals(msg.getPointFormats().getValue(), pointFormats);
        assertTrue(pointFormatLength == msg.getPointFormatsLength().getValue());
    }
}
