/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 * <p>
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.Charset;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HttpsRequestHandlerTest {

    private TlsContext context;
    private HttpsRequestMessage message;
    private HttpsRequestHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();

        String rawMessage = "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";
        HttpsRequestParser parser = new HttpsRequestParser(0, rawMessage.getBytes(Charset.forName("UTF-8")),
                ProtocolVersion.TLS12);
        message = parser.parse();

        handler = new HttpsRequestHandler(context);
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof HttpsRequestParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new HttpsRequestMessage()) instanceof HttpsRequestPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new HttpsRequestMessage()) instanceof HttpsRequestSerializer);
    }

    @Test
    public void testAdjustTLSContext() {
        handler.adjustTLSContext(message);
        assertEquals(context.getHttpContext().getLastRequestPath(), message.getRequestPath().getValue());
    }
}
