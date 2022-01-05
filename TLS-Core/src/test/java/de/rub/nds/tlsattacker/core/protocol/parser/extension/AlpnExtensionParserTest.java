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
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class AlpnExtensionParserTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ExtensionType.ALPN, ArrayConverter.hexStringToByteArray("0010000e000c02683208687474702f312e31"), 14, 0,
                12, ArrayConverter.hexStringToByteArray("02683208687474702f312e31") } });
    }

    private final ExtensionType extensionType;
    private final byte[] expectedBytes;
    private final int extensionLength;
    private final int startParsing;
    private final int proposedAlpnProtocolsLength;
    private final byte[] proposedAlpnProtocols;
    private AlpnExtensionParser parser;
    private AlpnExtensionMessage message;

    public AlpnExtensionParserTest(ExtensionType extensionType, byte[] expectedBytes, int extensionLength,
        int startParsing, int alpnExtensionLength, byte[] alpnAnnouncedProtocols) {
        this.extensionType = extensionType;
        this.expectedBytes = expectedBytes;
        this.extensionLength = extensionLength;
        this.startParsing = startParsing;
        this.proposedAlpnProtocolsLength = alpnExtensionLength;
        this.proposedAlpnProtocols = alpnAnnouncedProtocols;
    }

    @Before
    public void setUp() {
        parser = new AlpnExtensionParser(startParsing, expectedBytes, Config.createConfig());
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();
        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());

        assertEquals(proposedAlpnProtocolsLength, (long) message.getProposedAlpnProtocolsLength().getValue());
        assertArrayEquals(proposedAlpnProtocols, message.getProposedAlpnProtocols().getValue());
    }

}
