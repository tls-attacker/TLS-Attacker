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
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class AlpnExtensionParserTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("000c02683208687474702f312e31"), 12,
            ArrayConverter.hexStringToByteArray("02683208687474702f312e31") } });
    }

    private final byte[] expectedBytes;
    private final int proposedAlpnProtocolsLength;
    private final byte[] proposedAlpnProtocols;
    private AlpnExtensionParser parser;
    private AlpnExtensionMessage message;

    public AlpnExtensionParserTest(byte[] expectedBytes, int alpnProtocolsLength, byte[] alpnAnnouncedProtocols) {
        this.expectedBytes = expectedBytes;
        this.proposedAlpnProtocolsLength = alpnProtocolsLength;
        this.proposedAlpnProtocols = alpnAnnouncedProtocols;
    }

    @Before
    public void setUp() {
        parser = new AlpnExtensionParser(new ByteArrayInputStream(expectedBytes), Config.createConfig());
    }

    @Test
    public void testParse() {
        message = new AlpnExtensionMessage();
        parser.parse(message);

        assertEquals(proposedAlpnProtocolsLength, (long) message.getProposedAlpnProtocolsLength().getValue());
        assertArrayEquals(proposedAlpnProtocols, message.getProposedAlpnProtocols().getValue());
    }

}
