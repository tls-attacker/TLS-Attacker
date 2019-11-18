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
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class UnknownExtensionParserTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { ArrayConverter.hexStringToByteArray("00230000"), ArrayConverter.hexStringToByteArray("00230000"),
                        ArrayConverter.hexStringToByteArray("0023"), 0, null, },
                { ArrayConverter.hexStringToByteArray("000f000101"), ArrayConverter.hexStringToByteArray("000f000101"),
                        ArrayConverter.hexStringToByteArray("000f"), 1, ArrayConverter.hexStringToByteArray("01"), },
                { ArrayConverter.hexStringToByteArray("000f00010100"),
                        ArrayConverter.hexStringToByteArray("000f000101"), ArrayConverter.hexStringToByteArray("000f"),
                        1, ArrayConverter.hexStringToByteArray("01"), },
                { ArrayConverter.hexStringToByteArray("00000000"), ArrayConverter.hexStringToByteArray("00000000"),
                        ArrayConverter.hexStringToByteArray("0000"), 0, null, },
                { ArrayConverter.hexStringToByteArray("0000FFFF"), ArrayConverter.hexStringToByteArray("0000FFFF"),
                        ArrayConverter.hexStringToByteArray("0000"), 0xFFFF, null, } });
    }

    private final byte[] array;
    private final byte[] message;
    private final byte[] type;
    private final Integer extensionLength;
    private final byte[] data;

    public UnknownExtensionParserTest(byte[] array, byte[] message, byte[] type, Integer extensionLength, byte[] data) {
        this.array = array;
        this.message = message;
        this.type = type;
        this.extensionLength = extensionLength;
        this.data = data;
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of parse method, of class UnknownExtensionParser.
     */
    @Test
    public void testParse() {
        UnknownExtensionParser parser = new UnknownExtensionParser(0, array);
        UnknownExtensionMessage unknownMessage = parser.parse();
        assertArrayEquals(message, unknownMessage.getExtensionBytes().getValue());
        if (type != null) {
            assertArrayEquals(type, unknownMessage.getExtensionType().getValue());
        } else {
            assertNull(unknownMessage.getExtensionType());
        }
        if (extensionLength != null) {
            assertTrue(extensionLength.intValue() == unknownMessage.getExtensionLength().getValue());
        } else {
            assertNull(unknownMessage.getExtensionLength());
        }
        if (data != null) {
            assertArrayEquals(data, unknownMessage.getExtensionData().getValue());
        } else {
            assertNull(unknownMessage.getExtensionData());
        }
    }
}
