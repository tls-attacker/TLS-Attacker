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
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.io.ByteArrayInputStream;
import java.util.Random;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class UnknownParserStressTest {

    private UnknownMessageParser parser;
    private final Config config = Config.createConfig();

    /**
     * Test of parse method, of class UnknownParser.
     */
    @Test
    @Category(IntegrationTests.class)
    public void testParse() {
        Random r = new Random(10);
        for (int i = 0; i < 100; i++) {
            byte[] array = new byte[r.nextInt(100)];
            if (array.length != 0) {
                r.nextBytes(array);
                UnknownMessage message = new UnknownMessage();
                message.getParser(new TlsContext(config), new ByteArrayInputStream(array));
                parser.parse(message);
                assertArrayEquals(array, message.getCompleteResultingMessage().getValue());
            }
        }
    }

}
