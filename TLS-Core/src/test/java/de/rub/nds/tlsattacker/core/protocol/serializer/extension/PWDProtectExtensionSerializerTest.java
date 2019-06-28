/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PWDProtectExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PWDProtectExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return PWDProtectExtensionParserTest.generateData();
    }

    private final byte[] expectedBytes;
    private final int start;
    private final ExtensionType type;
    private final int extensionLength;
    private final int usernameLength;
    private final byte[] username;
    private PWDProtectExtensionMessage message;
    private PWDProtectExtensionSerializer serializer;

    public PWDProtectExtensionSerializerTest(byte[] expectedBytes, int start, ExtensionType type, int extensionLength,
            int usernameLength, byte[] username) {
        this.expectedBytes = expectedBytes;
        this.start = start;
        this.type = type;
        this.extensionLength = extensionLength;
        this.usernameLength = usernameLength;
        this.username = username;
    }

    @Before
    public void setUp() {
        message = new PWDProtectExtensionMessage();
        serializer = new PWDProtectExtensionSerializer(message);
    }

    @Test
    public void testSerializeExtensionContent() {
        message.setExtensionType(type.getValue());
        message.setExtensionLength(extensionLength);
        message.setUsername(username);
        message.setUsernameLength(usernameLength);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }

}