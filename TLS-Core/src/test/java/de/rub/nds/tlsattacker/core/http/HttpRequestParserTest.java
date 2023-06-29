/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http;

import static org.junit.Assert.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import org.junit.Before;
import org.junit.Test;

public class HttpRequestParserTest {

    private final Config config = Config.createConfig();

    public HttpRequestParserTest() {}

    @Before
    public void setUp() {}

    /** Test of parseMessageContent method, of class HttpsRequestParser with an invalid request. */
    @Test(expected = EndOfStreamException.class)
    public void testParseMessageContentFailed() {
        HttpRequestParser parser =
                new HttpRequestParser(
                        new ByteArrayInputStream(
                                ArrayConverter.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAA")));
        HttpRequestMessage message = new HttpRequestMessage();
        parser.parse(message);
    }

    /** Test of parseMessageContent method, of class HttpsRequestParser with an valid request. */
    @Test
    public void testParseMessageContentSuccess() {
        String stringMessage =
                "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";

        HttpRequestParser parser =
                new HttpRequestParser(
                        new ByteArrayInputStream(stringMessage.getBytes(Charset.forName("UTF-8"))));
        HttpRequestMessage message = new HttpRequestMessage();
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
