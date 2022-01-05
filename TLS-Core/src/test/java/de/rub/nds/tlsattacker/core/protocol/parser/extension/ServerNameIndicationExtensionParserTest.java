/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ServerNameIndicationExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            // case 1: completion.amazon.com
            { ArrayConverter.hexStringToByteArray("0018000015636f6d706c6574696f6e2e616d617a6f6e2e636f6d"), 24,
                ArrayConverter.hexStringToByteArray("000015636f6d706c6574696f6e2e616d617a6f6e2e636f6d"), },
            // case 2: guzzoni.apple.com
            { ArrayConverter.hexStringToByteArray("001400001167757a7a6f6e692e6170706c652e636f6d"), 20,
                ArrayConverter.hexStringToByteArray("00001167757a7a6f6e692e6170706c652e636f6d"), },
            // case 3: www.google.com, test.dummy.com
            { ArrayConverter
                .hexStringToByteArray("002200000e7777772e676f6f676c652e636f6d00000e746573742e64756d6d792e636f6d"), 34,
                ArrayConverter
                    .hexStringToByteArray("00000e7777772e676f6f676c652e636f6d00000e746573742e64756d6d792e636f6d") } });
    }

    private final byte[] extension;
    private final int sniListLength;
    private final byte[] sniListBytes;

    public ServerNameIndicationExtensionParserTest(byte[] extension, int sniListLength, byte[] sniListBytes) {
        this.extension = extension;
        this.sniListLength = sniListLength;
        this.sniListBytes = sniListBytes;
    }

    /**
     * Test of parseExtensionMessageContent method, of class ServerNameIndicationExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        ServerNameIndicationExtensionParser parser =
            new ServerNameIndicationExtensionParser(new ByteArrayInputStream(extension), Config.createConfig());
        ServerNameIndicationExtensionMessage msg = new ServerNameIndicationExtensionMessage();
        parser.parse(msg);
        assertArrayEquals(msg.getServerNameListBytes().getValue(), sniListBytes);
        assertEquals(sniListLength, msg.getServerNameListLength().getValue().intValue());
    }
}
