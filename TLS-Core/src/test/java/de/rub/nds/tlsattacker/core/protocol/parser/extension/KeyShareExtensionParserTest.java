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
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class KeyShareExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("002800260024001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("002800260024001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                        ExtensionType.KEY_SHARE_OLD,
                        38,
                        36,
                        ArrayConverter
                                .hexStringToByteArray("001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c") } });
    }

    private byte[] extension;
    private int start;
    private byte[] completeExtension;
    private ExtensionType type;
    private int extensionLength;
    private int ksListLength;
    private byte[] ksListBytes;

    public KeyShareExtensionParserTest(byte[] extension, int start, byte[] completeExtension, ExtensionType type,
            int extensionLength, int ksListLength, byte[] ksListBytes) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.ksListLength = ksListLength;
        this.ksListBytes = ksListBytes;
    }

    /**
     * Test of parseExtensionMessageContent method, of class
     * KeyShareExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        KeyShareExtensionParser parser = new KeyShareExtensionParser(start, extension, ExtensionType.KEY_SHARE);
        KeyShareExtensionMessage msg = parser.parse();
        assertArrayEquals(msg.getExtensionBytes().getValue(), completeExtension);
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertTrue(extensionLength == msg.getExtensionLength().getValue());
        assertArrayEquals(msg.getKeyShareListBytes().getValue(), ksListBytes);
        assertTrue(ksListLength == msg.getKeyShareListLength().getValue());
    }

}
