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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PWDProtectExtensionParserTest {

    /**
     * Generate test data for the parser and serializer
     *
     * Note that the "username" is not actually an encrypted byte string in this test. The parser and serializer don't
     * really care about that. This is just to test if the field is extracted correctly. The actual
     * encryption/decryption is done by the handler/preparator.
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("0466726564"), 4,
            ArrayConverter.hexStringToByteArray("66726564") } });
    }

    private final byte[] expectedBytes;
    private final int usernameLength;
    private final byte[] username;

    public PWDProtectExtensionParserTest(byte[] expectedBytes, int usernameLength, byte[] username) {
        this.expectedBytes = expectedBytes;
        this.usernameLength = usernameLength;
        this.username = username;
    }

    @Test
    public void testParseExtensionMessageContent() {
        PWDProtectExtensionParser parser = new PWDProtectExtensionParser(new ByteArrayInputStream(expectedBytes));
        PWDProtectExtensionMessage msg = new PWDProtectExtensionMessage();
        parser.parse(msg);
        assertEquals(usernameLength, (long) msg.getUsernameLength().getValue());
        assertArrayEquals(username, msg.getUsername().getValue());
    }
}
