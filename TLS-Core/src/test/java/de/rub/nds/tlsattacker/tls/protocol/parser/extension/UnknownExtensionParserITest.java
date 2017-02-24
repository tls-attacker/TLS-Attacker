/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import de.rub.nds.tlsattacker.tests.IntegrationTest;
import de.rub.nds.tlsattacker.tls.exceptions.ParserException;
import de.rub.nds.tlsattacker.tls.protocol.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.experimental.categories.Category;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownExtensionParserITest {

    private static final Logger LOGGER = LogManager.getLogger(UnknownExtensionParserITest.class);

    public UnknownExtensionParserITest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Try to parse alot of byte arrays into UnknownExtensionMessages and check
     * that everything is parseable
     */
    @Test
    @Category(IntegrationTest.class)
    public void testParser() {
        Random r = new Random(0);
        for (int i = 0; i < 100000; i++) {
            int length = r.nextInt(100000);
            byte[] bytesToParse = new byte[length];
            r.nextBytes(bytesToParse);
            int start = r.nextInt(100);
            if (bytesToParse.length > start) {
                UnknownExtensionParser parser = new UnknownExtensionParser(start, bytesToParse);
                UnknownExtensionMessage extension = parser.parse();
            }
        }

    }
}