/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.http;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.state.Context;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class HttpRequestPreparatorTest {

    private HttpContext context;
    private HttpRequestMessage message;
    private HttpRequestPreparator preparator;

    @Before
    public void setUp() {
        context = new HttpContext(new Context(new Config()));

        String rawMessage = "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";
        HttpRequestParser parser =
            new HttpRequestParser(new ByteArrayInputStream(rawMessage.getBytes(Charset.forName("UTF-8"))));
        message = new HttpRequestMessage();
        parser.parse(message);
        preparator = new HttpRequestPreparator(context, message);
    }

    @Test
    public void testPrepareProtocolMessageContents() {
        preparator.prepareHttpMessageContents();

        assertEquals(context.getConfig().getDefaultHttpsRequestPath(), message.getRequestPath().getOriginalValue());
        assertEquals("HTTP/1.1", message.getRequestProtocol().getOriginalValue());
        assertEquals("GET", message.getRequestType().getOriginalValue());
        assertEquals(2, message.getHeader().size());

    }
}
