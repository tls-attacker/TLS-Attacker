/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ServerNameIndicationExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] 
        {
        	// case 1: completion.amazon.com
        	{
        		new byte[]{0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00, 0x00, 0x15, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x2e, 0x63, 0x6f, 0x6d},
        		0,
        		new byte[]{0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00, 0x00, 0x15, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x2e, 0x63, 0x6f, 0x6d},
        		ExtensionType.SERVER_NAME_INDICATION,
        		26,
        		24,
        		new byte[]{0x00, 0x00, 0x15, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x2e, 0x63, 0x6f, 0x6d}        		
        	},
        	// case 2: guzzoni.apple.com
        	{
        		new byte[]{0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00, 0x00, 0x11, 0x67, 0x75, 0x7a, 0x7a, 0x6f, 0x6e, 0x69, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d},
        		0,
        		new byte[]{0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00, 0x00, 0x11, 0x67, 0x75, 0x7a, 0x7a, 0x6f, 0x6e, 0x69, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d},
        		ExtensionType.SERVER_NAME_INDICATION,
        		22,
        		20,
        		new byte[]{0x00, 0x00, 0x11, 0x67, 0x75, 0x7a, 0x7a, 0x6f, 0x6e, 0x69, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d},
        	}
        }); 
    }

    private final byte[] extension;
    private final int start;
    private final byte[] completeExtension;
    private final ExtensionType type;
    private final int extensionLength;
    private final int sniListLength;
    private final byte[] sniListBytes;

    public ServerNameIndicationExtensionParserTest(byte[] extension, int start, byte[] completeExtension,
            ExtensionType type, int extensionLength, int sniListLength, byte[] sniListBytes) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.sniListLength = sniListLength;
        this.sniListBytes = sniListBytes;
    }

    /**
     * Test of parseExtensionMessageContent method, of class
     * ServerNameIndicationExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        ServerNameIndicationExtensionParser parser = new ServerNameIndicationExtensionParser(start, extension);
        ServerNameIndicationExtensionMessage msg = parser.parse();
        assertArrayEquals(msg.getExtensionBytes().getValue(), completeExtension);
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertTrue(extensionLength == msg.getExtensionLength().getValue());
        assertArrayEquals(msg.getServerNameListBytes().getValue(), sniListBytes);
        assertTrue(sniListLength == msg.getServerNameListLength().getValue());
    }
}
