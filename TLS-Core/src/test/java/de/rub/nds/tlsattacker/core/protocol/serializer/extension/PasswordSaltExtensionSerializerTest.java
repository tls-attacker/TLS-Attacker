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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PasswordSaltExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PasswordSaltExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return PasswordSaltExtensionParserTest.generateData();
    }

    private final byte[] expectedBytes;
    private final int start;
    private final ExtensionType type;
    private final int extensionLength;
    private final int saltLength;
    private final byte[] salt;
    private PasswordSaltExtensionSerializer serializer;
    private PasswordSaltExtensionMessage msg;

    public PasswordSaltExtensionSerializerTest(byte[] expectedBytes, int start, ExtensionType type,
            int extensionLength, int saltLength, byte[] salt) {
        this.expectedBytes = expectedBytes;
        this.start = start;
        this.type = type;
        this.extensionLength = extensionLength;
        this.saltLength = saltLength;
        this.salt = salt;
    }

    @Before
    public void setUp() {
        msg = new PasswordSaltExtensionMessage();
        serializer = new PasswordSaltExtensionSerializer(msg);
    }

    @Test
    public void testSerializeExtensionContent() {
        msg.setExtensionType(type.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setSalt(salt);
        msg.setSaltLength(saltLength);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
