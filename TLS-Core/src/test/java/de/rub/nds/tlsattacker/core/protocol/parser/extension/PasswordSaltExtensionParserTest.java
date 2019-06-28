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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PasswordSaltExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { {
                ArrayConverter.hexStringToByteArray("001f00120010843711c21d47ce6e6383cdda37e47da3"), 0,
                ExtensionType.PASSWORD_SALT, 18, 16,
                ArrayConverter.hexStringToByteArray("843711c21d47ce6e6383cdda37e47da3") } });
    }

    private final byte[] expectedBytes;
    private final int start;
    private final ExtensionType type;
    private final int extensionLength;
    private final int saltLength;
    private final byte[] salt;

    public PasswordSaltExtensionParserTest(byte[] expectedBytes, int start, ExtensionType type, int extensionLength,
            int saltLength, byte[] salt) {
        this.expectedBytes = expectedBytes;
        this.start = start;
        this.type = type;
        this.extensionLength = extensionLength;
        this.saltLength = saltLength;
        this.salt = salt;
    }

    @Test
    public void testParseExtensionMessageContent() {
        PasswordSaltExtensionParser parser = new PasswordSaltExtensionParser(start, expectedBytes);
        PasswordSaltExtensionMessage msg = parser.parse();
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertEquals(extensionLength, (long) msg.getExtensionLength().getValue());
        assertEquals(saltLength, (long) msg.getSaltLength().getValue());
        assertArrayEquals(salt, msg.getSalt().getValue());
    }

}
