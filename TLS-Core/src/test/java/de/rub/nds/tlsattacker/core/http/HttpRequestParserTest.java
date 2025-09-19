/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.EndOfStreamException;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class HttpRequestParserTest {

    /** Test of parseMessageContent method, of class HttpsRequestParser with an invalid request. */
    @Test
    void testParseMessageContentFailed() {
        HttpRequestParser parser =
                new HttpRequestParser(
                        new ByteArrayInputStream(
                                DataConverter.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAA")));
        HttpRequestMessage message = new HttpRequestMessage();
        assertThrows(EndOfStreamException.class, () -> parser.parse(message));
    }

    /** Test of parseMessageContent method, of class HttpsRequestParser with an valid request. */
    @Test
    void testParseMessageContentSuccess() {
        String stringMessage =
                "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";

        HttpRequestParser parser =
                new HttpRequestParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        HttpRequestMessage message = new HttpRequestMessage();
        parser.parse(message);

        assertEquals("GET", message.getRequestType().getValue());
        assertEquals("/index.html", message.getRequestPath().getValue());
        assertEquals("HTTP/1.1", message.getRequestProtocol().getValue());

        assertEquals("User-Agent", message.getHeader().get(0).getHeaderName().getValue());
        assertEquals("Test", message.getHeader().get(0).getHeaderValue().getValue());

        assertEquals("Host", message.getHeader().get(1).getHeaderName().getValue());
        assertEquals("www.rub.de", message.getHeader().get(1).getHeaderValue().getValue());
    }

    /** Test parsing request with regex metacharacters in headers - issue #661 */
    @Test
    void testParseRequestWithRegexMetacharactersInHeaders() {
        String stringMessage =
                "GET /index.html HTTP/1.1\r\n[*]: value1\r\n$test: value2\r\n^header: value3\r\n\r\n";

        HttpRequestParser parser =
                new HttpRequestParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        HttpRequestMessage message = new HttpRequestMessage();
        parser.parse(message);

        assertEquals("GET", message.getRequestType().getValue());
        assertEquals("/index.html", message.getRequestPath().getValue());
        assertEquals("HTTP/1.1", message.getRequestProtocol().getValue());

        assertEquals("[*]", message.getHeader().get(0).getHeaderName().getValue());
        assertEquals("value1", message.getHeader().get(0).getHeaderValue().getValue());

        assertEquals("$test", message.getHeader().get(1).getHeaderName().getValue());
        assertEquals("value2", message.getHeader().get(1).getHeaderValue().getValue());

        assertEquals("^header", message.getHeader().get(2).getHeaderName().getValue());
        assertEquals("value3", message.getHeader().get(2).getHeaderValue().getValue());
    }
}
