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
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.UserMappingExtensionMessage;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class UserMappingExtensionParserTest {

    private final ExtensionType extensionType = ExtensionType.USER_MAPPING;
    private final byte[] extensionBytes = ArrayConverter.hexStringToByteArray("0006000140");
    private final int extensionLength = 1;
    private final int startposition = 0;
    private final UserMappingExtensionHintType hintType = UserMappingExtensionHintType.UPN_DOMAIN_HINT;
    private UserMappingExtensionParser parser;
    private UserMappingExtensionMessage message;

    @Before
    public void setUp() {
        parser = new UserMappingExtensionParser(startposition, extensionBytes);
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();
        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
        assertEquals(hintType.getValue(), (long) message.getUserMappingType().getValue());
    }
}
