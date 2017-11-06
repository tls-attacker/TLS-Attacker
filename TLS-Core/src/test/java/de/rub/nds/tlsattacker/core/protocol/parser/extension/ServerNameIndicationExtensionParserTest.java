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
        return Arrays.asList(new Object[][] {}); // TODO collect a real sni
                                                 // message
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
