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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class PaddingExtensionParserTest {

    /**
     * Parameterized set up of the test vector.
     *
     * @return test vector (extensionType, extensionLength, extensionPayload, expectedBytes)
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { new byte[] { 0, 0, 0, 0, 0, 0 }, ArrayConverter.hexStringToByteArray("000000000000") } });
    }

    private final byte[] extensionPayload;
    private final byte[] expectedBytes;
    private PaddingExtensionParser parser;
    private PaddingExtensionMessage message;

    public PaddingExtensionParserTest(byte[] extensionPayload, byte[] expectedBytes) {
        this.extensionPayload = extensionPayload;
        this.expectedBytes = expectedBytes;
    }

    @Before
    public void setUp() {
        parser = new PaddingExtensionParser(new ByteArrayInputStream(expectedBytes), Config.createConfig());
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = new PaddingExtensionMessage();
        parser.parse(message);
        assertArrayEquals(extensionPayload, message.getPaddingBytes().getValue());
    }

}
