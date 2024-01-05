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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class HttpResponseParserTest {

    private Config config;

    public void setUp() {
        config = Config.createConfig();
    }

    /**
     * Test of parseMessageContent method, of class HttpsResponseParser with an invalid response.
     */
    @Test
    public void testParseMessageContentFailed() {
        HttpResponseParser parser =
                new HttpResponseParser(
                        new ByteArrayInputStream(
                                ArrayConverter.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAA")));
        assertThrows(EndOfStreamException.class, () -> parser.parse(new HttpResponseMessage()));
    }

    /** Test of parseMessageContent method, of class HttpsResponseParser with a valid response. */
    @Test
    public void testParseMessageContentSuccess() {
        String message =
                "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\n"
                        + "Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\nContent-Length: 88\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\ntest";

        HttpResponseParser parser =
                new HttpResponseParser(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        HttpResponseMessage parsedMessage = new HttpResponseMessage();
        parser.parse(parsedMessage);

        assertEquals(parsedMessage.getResponseStatusCode().getValue(), "200 OK");
        assertEquals(parsedMessage.getResponseProtocol().getValue(), "HTTP/1.1");
        assertEquals(parsedMessage.getResponseContent().getValue(), "test");

        assertEquals(parsedMessage.getHeader().get(0).getHeaderName().getValue(), "Date");
        assertEquals(
                parsedMessage.getHeader().get(0).getHeaderValue().getValue(),
                "Mon, 27 Jul 2009 12:28:53 GMT");

        assertEquals(parsedMessage.getHeader().get(1).getHeaderName().getValue(), "Server");
        assertEquals(
                parsedMessage.getHeader().get(1).getHeaderValue().getValue(),
                "Apache/2.2.14 (Win32)");

        assertEquals(parsedMessage.getHeader().get(2).getHeaderName().getValue(), "Last-Modified");
        assertEquals(
                parsedMessage.getHeader().get(2).getHeaderValue().getValue(),
                "Wed, 22 Jul 2009 19:15:56 GMT");

        assertEquals(parsedMessage.getHeader().get(3).getHeaderName().getValue(), "Content-Length");
        assertEquals(parsedMessage.getHeader().get(3).getHeaderValue().getValue(), "88");

        assertEquals(parsedMessage.getHeader().get(4).getHeaderName().getValue(), "Content-Type");
        assertEquals(parsedMessage.getHeader().get(4).getHeaderValue().getValue(), "text/html");

        assertEquals(parsedMessage.getHeader().get(5).getHeaderName().getValue(), "Connection");
        assertEquals(parsedMessage.getHeader().get(5).getHeaderValue().getValue(), "Closed");
    }
}
