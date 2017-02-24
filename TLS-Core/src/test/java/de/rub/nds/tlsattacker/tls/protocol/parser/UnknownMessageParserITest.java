/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tests.IntegrationTest;
import de.rub.nds.tlsattacker.tls.protocol.handshake.UnknownMessage;
import java.util.Random;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.experimental.categories.Category;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownMessageParserITest {

    private UnknownMessageParser parser;

    public UnknownMessageParserITest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of parse method, of class UnknownMessageParser.
     */
    @Test
    @Category(IntegrationTest.class)
    public void testParse() {
        Random r = new Random(10);
        for (int i = 0; i < 100; i++) {
            byte[] array = new byte[r.nextInt(100)];
            if (array.length != 0) {
                r.nextBytes(array);
                parser = new UnknownMessageParser(0, array);
                UnknownMessage message = parser.parse();
                assertArrayEquals(array, message.getCompleteResultingMessage().getValue());
            }
        }
    }

}
