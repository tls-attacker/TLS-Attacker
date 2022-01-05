/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class AlertParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { new byte[] { 1, 2 }, (byte) 1, (byte) 2 },
            { new byte[] { 4, 3 }, (byte) 4, (byte) 3 } });
    }

    private final byte[] message;
    private final byte level;
    private final byte description;
    private final Config config = Config.createConfig();

    public AlertParserTest(byte[] message, byte level, byte description) {
        this.message = message;
        this.level = level;
        this.description = description;
    }

    /**
     * Test of parse method, of class AlertParser.
     */
    @Test
    public void testParse() {
        AlertParser parser = new AlertParser(new ByteArrayInputStream(message), ProtocolVersion.TLS12, config);
        AlertMessage alert = new AlertMessage();
        parser.parse(alert);
        assertArrayEquals(message, alert.getCompleteResultingMessage().getValue());
        assertTrue(level == alert.getLevel().getValue());
        assertTrue(description == alert.getDescription().getValue());
    }
}
