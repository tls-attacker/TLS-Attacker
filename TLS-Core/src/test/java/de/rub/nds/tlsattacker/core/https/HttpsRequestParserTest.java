/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class HttpsRequestParserTest {

    private final Config config = Config.createConfig();

    public HttpsRequestParserTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of parseMessageContent method, of class HttpsRequestParser with an invalid request.
     */
    @Test(expected = EndOfStreamException.class)
    public void testParseMessageContentFailed() {
        HttpsRequestParser parser = new HttpsRequestParser(
            new ByteArrayInputStream(ArrayConverter.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAA")));
        HttpsRequestMessage message = new HttpsRequestMessage();
        parser.parse(message);
    }

    /**
     * Test of parseMessageContent method, of class HttpsRequestParser with an valid request.
     */
    @Test
    public void testParseMessageContentSuccess() {
        String stringMessage = "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";

        HttpsRequestParser parser =
            new HttpsRequestParser(new ByteArrayInputStream(stringMessage.getBytes(Charset.forName("UTF-8"))));
        HttpsRequestMessage message = new HttpsRequestMessage();
        parser.parse(message);

        assertEquals(message.getRequestType().getValue(), "GET");
        assertEquals(message.getRequestPath().getValue(), "/index.html");
        assertEquals(message.getRequestProtocol().getValue(), "HTTP/1.1");

        assertEquals(message.getHeader().get(0).getHeaderName().getValue(), "User-Agent");
        assertEquals(message.getHeader().get(0).getHeaderValue().getValue(), "Test");

        assertEquals(message.getHeader().get(1).getHeaderName().getValue(), "Host");
        assertEquals(message.getHeader().get(1).getHeaderValue().getValue(), "www.rub.de");
    }

}
