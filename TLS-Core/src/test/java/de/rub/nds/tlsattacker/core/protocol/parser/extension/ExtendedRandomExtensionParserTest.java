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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ExtendedRandomExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ArrayConverter.hexStringToByteArray("AB"), ArrayConverter.hexStringToByteArray("0001AB") } });
    }

    private final byte[] extendedRandom;
    private final byte[] expectedBytes;
    private ExtendedRandomExtensionParser parser;
    private ExtendedRandomExtensionMessage message;

    /**
     * Constructor for parameterized setup.
     *
     * @param extensionType
     * @param extensionLength
     * @param extendedRandom
     * @param expectedBytes
     */
    public ExtendedRandomExtensionParserTest(byte[] extendedRandom, byte[] expectedBytes) {
        this.extendedRandom = extendedRandom;
        this.expectedBytes = expectedBytes;
    }

    @Before
    public void setUp() {
        parser = new ExtendedRandomExtensionParser(new ByteArrayInputStream(expectedBytes));
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = new ExtendedRandomExtensionMessage();
        parser.parse(message);
        assertArrayEquals(extendedRandom, message.getExtendedRandom().getValue());

    }

}
