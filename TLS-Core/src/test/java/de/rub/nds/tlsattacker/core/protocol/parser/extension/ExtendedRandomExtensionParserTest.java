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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import org.junit.Before;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class ExtendedRandomExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ExtensionType.EXTENDED_RANDOM, 3,
            ArrayConverter.hexStringToByteArray("AB"), ArrayConverter.hexStringToByteArray("002800030001AB"), 0 } });
    }

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] extendedRandom;
    private final byte[] expectedBytes;
    private final int startParsing;
    private ExtendedRandomExtensionParser parser;
    private ExtendedRandomExtensionMessage message;

    /**
     * Constructor for parameterized setup.
     *
     * @param extensionType
     * @param extensionLength
     * @param extendedRandom
     * @param expectedBytes
     * @param startParsing
     */
    public ExtendedRandomExtensionParserTest(ExtensionType extensionType, int extensionLength, byte[] extendedRandom,
        byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.extendedRandom = extendedRandom;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Before
    public void setUp() {
        parser = new ExtendedRandomExtensionParser(startParsing, expectedBytes, Config.createConfig());
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();

        assertArrayEquals(ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
        assertArrayEquals(extendedRandom, message.getExtendedRandom().getValue());

    }

}
