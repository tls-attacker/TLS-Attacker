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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SupportedVersionsExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("0C000203000301030203037F14"), 12,
            ArrayConverter.hexStringToByteArray("000203000301030203037F14") } });
    }

    private final byte[] extension;
    private final int versionListLength;
    private final byte[] versionList;
    private final Config config = Config.createConfig();

    public SupportedVersionsExtensionParserTest(byte[] extension, int versionListLength, byte[] versionList) {
        this.extension = extension;
        this.versionListLength = versionListLength;
        this.versionList = versionList;
    }

    /**
     * Test of parseExtensionMessageContent method, of class SupportedVersionsExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        TlsContext tlsContext = new TlsContext(config);
        SupportedVersionsExtensionParser parser =
            new SupportedVersionsExtensionParser(new ByteArrayInputStream(extension), tlsContext);
        SupportedVersionsExtensionMessage msg = new SupportedVersionsExtensionMessage();
        parser.parse(msg);
        assertArrayEquals(msg.getSupportedVersions().getValue(), versionList);
        assertTrue(versionListLength == msg.getSupportedVersionsLength().getValue());
    }

}
