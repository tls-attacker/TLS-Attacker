/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class UnknownExtensionParserTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { new byte[0] }, { ArrayConverter.hexStringToByteArray("01") },
            { ArrayConverter.hexStringToByteArray("0100") } });
    }

    private final byte[] message;

    public UnknownExtensionParserTest(byte[] message) {
        this.message = message;
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of parse method, of class UnknownExtensionParser.
     */
    @Test
    public void testParse() {
        UnknownExtensionParser parser =
            new UnknownExtensionParser(new ByteArrayInputStream(message), Config.createConfig());
        UnknownExtensionMessage unknownMessage = new UnknownExtensionMessage();
        parser.parseExtensionMessageContent(unknownMessage);
        assertArrayEquals(message, unknownMessage.getExtensionData().getValue());

    }
}
