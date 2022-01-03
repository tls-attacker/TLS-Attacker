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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ClientAuthzExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("0400010203"), 4,
            ArrayConverter.hexStringToByteArray("00010203") } });
    }

    private final byte[] expectedBytes;
    private final int authzFormatListLength;
    private final byte[] authzFormatList;
    private ClientAuthzExtensionParser parser;
    private ClientAuthzExtensionMessage msg;

    public ClientAuthzExtensionParserTest(byte[] expectedBytes, int authzFormatListLength, byte[] authzFormatList) {
        this.expectedBytes = expectedBytes;
        this.authzFormatListLength = authzFormatListLength;
        this.authzFormatList = authzFormatList;
    }

    @Test
    public void testParseExtensionMessageContent() {
        parser = new ClientAuthzExtensionParser(new ByteArrayInputStream(expectedBytes), Config.createConfig());
        msg = new ClientAuthzExtensionMessage();
        parser.parse(msg);
        assertEquals(authzFormatListLength, (long) msg.getAuthzFormatListLength().getValue());
        assertArrayEquals(authzFormatList, msg.getAuthzFormatList().getValue());
    }
}
