/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class EncryptThenMacExtensionParserTest {
    private final ExtensionType extensionType = ExtensionType.ENCRYPT_THEN_MAC;
    private final byte[] expectedBytes = new byte[] { 0x00, 0x16, 0x00, 0x00 };
    private final int extensionLength = 0;
    private final int startPosition = 0;
    private EncryptThenMacExtensionParser parser;
    private EncryptThenMacExtensionMessage message;

    @Before
    public void setUp() {
        parser = new EncryptThenMacExtensionParser(startPosition, expectedBytes, Config.createConfig());
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();

        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
    }
}
