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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class GreaseExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("1a1a000a0102030405060708090a"), 0,
            ArrayConverter.hexStringToByteArray("1a1a000a0102030405060708090a"), ExtensionType.GREASE_01, 10,
            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 } } });
    }

    private final byte[] extension;
    private final int start;
    private final byte[] completeExtension;
    private final ExtensionType type;
    private final int extensionLength;
    private final byte[] randomData;

    public GreaseExtensionParserTest(byte[] extension, int start, byte[] completeExtension, ExtensionType type,
        int extensionLength, byte[] randomData) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.randomData = randomData;
    }

    /**
     * Test of parseExtensionMessageContent method, of class HeartbeatExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        GreaseExtensionParser parser = new GreaseExtensionParser(start, extension, Config.createConfig());
        GreaseExtensionMessage msg = parser.parse();
        assertArrayEquals(msg.getExtensionBytes().getValue(), completeExtension);
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertArrayEquals(type.getValue(), msg.getType().getValue());
        assertTrue(extensionLength == msg.getExtensionLength().getValue());
        assertArrayEquals(randomData, msg.getRandomData().getValue());
        assertArrayEquals(randomData, msg.getData());
    }

}
