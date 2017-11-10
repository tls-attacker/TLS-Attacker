/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.util.Random;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class UnknownMessageParserStressTest {

    private UnknownMessageParser parser;

    @Before
    public void before() {
        Configurator.setRootLevel(Level.OFF);
    }

    @After
    public void after() {
        Configurator.setRootLevel(Level.INFO);
    }

    /**
     * Test of parse method, of class UnknownMessageParser.
     */
    @Test
    @Category(IntegrationTests.class)
    public void testParse() {
        Random r = new Random(10);
        for (int i = 0; i < 100; i++) {
            byte[] array = new byte[r.nextInt(100)];
            if (array.length != 0) {
                r.nextBytes(array);
                parser = new UnknownMessageParser(0, array, ProtocolVersion.TLS12);
                UnknownMessage message = parser.parse();
                assertArrayEquals(array, message.getCompleteResultingMessage().getValue());
            }
        }
    }

}
