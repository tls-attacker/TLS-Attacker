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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import org.junit.Before;
import org.junit.Test;

public class HttpRequestHandlerTest {

    private HttpContext context;
    private HttpRequestMessage message;
    private HttpRequestHandler handler;

    @Before
    public void setUp() {
        context = new HttpContext(new Context(new Config()));

        String rawMessage =
                "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";
        HttpRequestParser parser =
                new HttpRequestParser(
                        new ByteArrayInputStream(rawMessage.getBytes(Charset.forName("UTF-8"))));
        message = new HttpRequestMessage();
        parser.parse(message);

        handler = new HttpRequestHandler(context);
    }

    @Test
    public void testadjustContext() {
        handler.adjustContext(message);
        assertEquals(context.getLastRequestPath(), message.getRequestPath().getValue());
    }
}
