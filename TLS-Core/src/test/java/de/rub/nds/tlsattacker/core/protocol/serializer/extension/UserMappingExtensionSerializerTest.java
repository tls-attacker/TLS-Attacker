/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.UserMappingExtensionMessage;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class UserMappingExtensionSerializerTest {
    private final ExtensionType extensionType = ExtensionType.USER_MAPPING;
    private final byte[] extensionBytes = ArrayConverter.hexStringToByteArray("0006000140");
    private final int extensionLength = 1;
    private final UserMappingExtensionHintType hintType = UserMappingExtensionHintType.UPN_DOMAIN_HINT;
    private UserMappingExtensionSerializer serializer;
    private UserMappingExtensionMessage msg;

    @Before
    public void setUp() {
        msg = new UserMappingExtensionMessage();
        serializer = new UserMappingExtensionSerializer(msg);
    }

    @Test
    public void testSerializeExtensionContent() {
        msg.setExtensionType(extensionType.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setUserMappingType(hintType.getValue());

        assertArrayEquals(extensionBytes, serializer.serialize());
    }
}
