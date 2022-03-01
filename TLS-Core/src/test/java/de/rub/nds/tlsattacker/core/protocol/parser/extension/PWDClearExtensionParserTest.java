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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PWDClearExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("0466726564"), 4, "fred" } });
    }

    private final byte[] expectedBytes;
    private final int usernameLength;
    private final String username;

    public PWDClearExtensionParserTest(byte[] expectedBytes, int usernameLength, String username) {
        this.expectedBytes = expectedBytes;
        this.usernameLength = usernameLength;
        this.username = username;
    }

    @Test
    public void testParseExtensionMessageContent() {
        PWDClearExtensionParser parser = new PWDClearExtensionParser(new ByteArrayInputStream(expectedBytes));
        PWDClearExtensionMessage msg = new PWDClearExtensionMessage();
        parser.parse(msg);
        assertEquals(usernameLength, (long) msg.getUsernameLength().getValue());
        assertEquals(username, msg.getUsername().getValue());
    }
}
