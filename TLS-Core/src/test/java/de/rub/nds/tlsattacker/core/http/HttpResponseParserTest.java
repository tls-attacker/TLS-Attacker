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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.exception.EndOfStreamException;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class HttpResponseParserTest {
    /**
     * Test of parseMessageContent method, of class HttpsResponseParser with an invalid response.
     */
    @Test
    void testParseMessageContentFailed() {
        HttpResponseParser parser =
                new HttpResponseParser(
                        new ByteArrayInputStream(
                                ArrayConverter.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAA")),
                        1000);
        HttpResponseMessage parsedMessage = new HttpResponseMessage();
        assertThrows(EndOfStreamException.class, () -> parser.parse(parsedMessage));
    }

    /** Test of parseMessageContent method, of class HttpsResponseParser with a valid response. */
    @Test
    void testParseMessageContentSuccess() {
        String message =
                "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\n"
                        + "Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\nContent-Length: 4\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\ntest";

        HttpResponseParser parser =
                new HttpResponseParser(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), 1000);
        HttpResponseMessage parsedMessage = new HttpResponseMessage();
        parser.parse(parsedMessage);

        assertEquals("200 OK", parsedMessage.getResponseStatusCode().getValue());
        assertEquals("HTTP/1.1", parsedMessage.getResponseProtocol().getValue());
        assertEquals("test", parsedMessage.getResponseContent().getValue());

        assertEquals("Date", parsedMessage.getHeader().get(0).getHeaderName().getValue());
        assertEquals(
                "Mon, 27 Jul 2009 12:28:53 GMT",
                parsedMessage.getHeader().get(0).getHeaderValue().getValue());

        assertEquals("Server", parsedMessage.getHeader().get(1).getHeaderName().getValue());
        assertEquals(
                "Apache/2.2.14 (Win32)",
                parsedMessage.getHeader().get(1).getHeaderValue().getValue());

        assertEquals("Last-Modified", parsedMessage.getHeader().get(2).getHeaderName().getValue());
        assertEquals(
                "Wed, 22 Jul 2009 19:15:56 GMT",
                parsedMessage.getHeader().get(2).getHeaderValue().getValue());

        assertEquals("Content-Length", parsedMessage.getHeader().get(3).getHeaderName().getValue());
        assertEquals("4", parsedMessage.getHeader().get(3).getHeaderValue().getValue());

        assertEquals("Content-Type", parsedMessage.getHeader().get(4).getHeaderName().getValue());
        assertEquals("text/html", parsedMessage.getHeader().get(4).getHeaderValue().getValue());

        assertEquals("Connection", parsedMessage.getHeader().get(5).getHeaderName().getValue());
        assertEquals("Closed", parsedMessage.getHeader().get(5).getHeaderValue().getValue());
    }

    @Test
    void testParseMessageContentMissingContent() {
        String message =
                "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\n"
                        + "Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\nContent-Length: 5\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\ntest";

        HttpResponseParser parser =
                new HttpResponseParser(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)), 1000);
        HttpResponseMessage parsedMessage = new HttpResponseMessage();
        assertThrows(EndOfStreamException.class, () -> parser.parse(parsedMessage));
    }

    @Test
    void testParseMessageContentTrailingContent() {
        String message =
                "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\n"
                        + "Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\nContent-Length: 3\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\ntest";

        var inputStream = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        HttpResponseParser parser = new HttpResponseParser(inputStream, 1000);
        HttpResponseMessage parsedMessage = new HttpResponseMessage();
        parser.parse(parsedMessage);
        assertEquals("Content-Length", parsedMessage.getHeader().get(3).getHeaderName().getValue());
        assertEquals("3", parsedMessage.getHeader().get(3).getHeaderValue().getValue());
        assertEquals("tes", parsedMessage.getResponseContent().getValue());
        assertEquals(1, inputStream.available());
    }
}
