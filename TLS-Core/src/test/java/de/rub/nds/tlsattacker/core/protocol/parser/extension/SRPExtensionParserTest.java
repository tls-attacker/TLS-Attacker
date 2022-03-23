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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
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
public class SRPExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { new byte[] { 0x04, 0x01, 0x02, 0x03, 0x04 }, 4, ArrayConverter.hexStringToByteArray("01020304") } });
    }

    private final byte[] extensionBytes;
    private final int srpIdentifierLength;
    private final byte[] srpIdentifier;
    private SRPExtensionParser parser;
    private SRPExtensionMessage message;
    private final Config config = Config.createConfig();

    public SRPExtensionParserTest(byte[] extensionBytes, int srpIdentifierLength, byte[] srpIdentifier) {
        this.extensionBytes = extensionBytes;
        this.srpIdentifierLength = srpIdentifierLength;
        this.srpIdentifier = srpIdentifier;
    }

    @Before
    public void setUp() {
        TlsContext tlsContext = new TlsContext(config);
        parser = new SRPExtensionParser(new ByteArrayInputStream(extensionBytes), tlsContext);

    }

    @Test
    public void testParseExtensionMessageContent() {
        message = new SRPExtensionMessage();
        parser.parse(message);

        assertEquals(srpIdentifierLength, (long) message.getSrpIdentifierLength().getValue());
        assertArrayEquals(srpIdentifier, message.getSrpIdentifier().getValue());

    }

}
