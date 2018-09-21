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
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class UnknownParserStressTest {

    private UnknownParser parser;

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
                parser = new UnknownParser(0, array, ProtocolVersion.TLS12);
                UnknownMessage message = parser.parse();
                assertArrayEquals(array, message.getCompleteResultingMessage().getValue());
            }
        }
    }

}
