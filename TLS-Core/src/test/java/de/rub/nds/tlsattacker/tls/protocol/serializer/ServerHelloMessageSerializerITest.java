/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tests.IntegrationTest;
import de.rub.nds.tlsattacker.tls.exceptions.ParserException;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ServerHelloMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ServerHelloMessageParserITest;
import de.rub.nds.tlsattacker.util.ArrayConverter;
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
public class ServerHelloMessageSerializerITest {

    private static final Logger LOGGER = LogManager.getLogger(ServerHelloMessageParserITest.class);

    public ServerHelloMessageSerializerITest() {
    }

    @Before
    public void setUp() {
    }

    @Test
    @Category(IntegrationTest.class)
    public void testParser() {
        Random r = new Random(0);
        for (int i = 0; i < 10000; i++) {
            ServerHelloMessage helloMessage = null;
            byte[] bytesToParse = null;
            try {
                int length = r.nextInt(10000);
                bytesToParse = new byte[length];
                r.nextBytes(bytesToParse);
                int start = r.nextInt(100);
                if (bytesToParse.length > start) {
                    bytesToParse[start] = 0x02;
                }
                ServerHelloMessageParser parser = new ServerHelloMessageParser(start, bytesToParse);
                helloMessage = parser.parse();
            } catch (ParserException E) {
                continue;
            }

            byte[] expected = helloMessage.getCompleteResultingMessage().getValue();
            ServerHelloMessageSerializer serializer = new ServerHelloMessageSerializer(helloMessage);
            byte[] result = serializer.serialize();
            LOGGER.debug(helloMessage.toString());
            LOGGER.debug("Bytes to parse:\t" + ArrayConverter.bytesToHexString(bytesToParse, false));
            LOGGER.debug("Expected:\t" + ArrayConverter.bytesToHexString(expected, false));
            LOGGER.debug("Result:\t" + ArrayConverter.bytesToHexString(result, false));
            ServerHelloMessageParser parser2 = new ServerHelloMessageParser(0, result);
            ServerHelloMessage serialized = parser2.parse();
            LOGGER.debug(serialized.toString());
            assertArrayEquals(result, expected);
            assertArrayEquals(serialized.getCompleteResultingMessage().getValue(), result);
        }
    }
}
