/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class UserMappingExtensionSerializerTest {
    private final byte[] extensionBytes = ArrayConverter.hexStringToByteArray("40");
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
        msg.setUserMappingType(hintType.getValue());

        assertArrayEquals(extensionBytes, serializer.serializeExtensionContent());
    }
}
