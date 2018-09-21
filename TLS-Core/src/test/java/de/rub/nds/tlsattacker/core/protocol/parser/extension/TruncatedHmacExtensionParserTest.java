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
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class TruncatedHmacExtensionParserTest {

    private final ExtensionType extensionType = ExtensionType.TRUNCATED_HMAC;
    private final byte[] expectedBytes = new byte[] { 0x00, 0x04, 0x00, 0x00 };
    private final int extensionLength = 0;
    private TruncatedHmacExtensionParser parser;
    private TruncatedHmacExtensionMessage message;

    @Before
    public void setUp() {
        parser = new TruncatedHmacExtensionParser(0, expectedBytes);
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();

        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
    }
}
