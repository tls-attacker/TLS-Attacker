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
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HRRKeyShareExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("00280002001D"), 0,
                ArrayConverter.hexStringToByteArray("00280002001D"), ExtensionType.KEY_SHARE_OLD, 2,
                ArrayConverter.hexStringToByteArray("001D") } });
    }

    private byte[] extension;
    private int start;
    private byte[] completeExtension;
    private ExtensionType type;
    private int extensionLength;
    private byte[] selectedGroup;

    public HRRKeyShareExtensionParserTest(byte[] extension, int start, byte[] completeExtension, ExtensionType type,
            int extensionLength, byte[] selectedGroup) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.selectedGroup = selectedGroup;
    }

    /**
     * Test of parseExtensionMessageContent method, of class
     * HRRKeyShareExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        HRRKeyShareExtensionParser parser = new HRRKeyShareExtensionParser(start, extension);
        HRRKeyShareExtensionMessage msg = parser.parse();
        assertArrayEquals(msg.getExtensionBytes().getValue(), completeExtension);
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertTrue(extensionLength == msg.getExtensionLength().getValue());
        assertArrayEquals(msg.getSelectedGroup().getValue(), selectedGroup);
    }

}
