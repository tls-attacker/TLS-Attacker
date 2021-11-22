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
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HeartbeatExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("01"), new byte[] { 1 } } }); // is
        // the
        // same for
        // TLS10 and
        // TLS11
    }

    private final byte[] extension;
    private final byte[] heartbeatMode;

    public HeartbeatExtensionParserTest(byte[] extension, byte[] heartbeatMode) {
        this.extension = extension;
        this.heartbeatMode = heartbeatMode;
    }

    /**
     * Test of parseExtensionMessageContent method, of class HeartbeatExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        HeartbeatExtensionParser parser =
            new HeartbeatExtensionParser(new ByteArrayInputStream(extension), Config.createConfig());
        HeartbeatExtensionMessage msg = new HeartbeatExtensionMessage();
        parser.parse(msg);
        assertArrayEquals(heartbeatMode, msg.getHeartbeatMode().getValue());
    }
}
