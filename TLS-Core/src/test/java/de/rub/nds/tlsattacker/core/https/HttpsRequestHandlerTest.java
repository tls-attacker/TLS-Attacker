/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class HttpsRequestHandlerTest {

    private TlsContext context;
    private HttpsRequestMessage message;
    private HttpsRequestHandler handler;
    private final Config config = Config.createConfig();

    @BeforeEach
    public void setUp() {
        context = new TlsContext();

        String rawMessage = "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";
        HttpsRequestParser parser =
            new HttpsRequestParser(0, rawMessage.getBytes(StandardCharsets.UTF_8), ProtocolVersion.TLS12, config);
        message = parser.parse();

        handler = new HttpsRequestHandler(context);
    }

    @Test
    public void testGetParser() {
        assertNotNull(handler.getParser(new byte[1], 0));
    }

    @Test
    public void testGetPreparator() {
        assertNotNull(handler.getPreparator(new HttpsRequestMessage()));
    }

    @Test
    public void testGetSerializer() {
        assertNotNull(handler.getSerializer(new HttpsRequestMessage()));
    }

    @Test
    public void testAdjustTLSContext() {
        handler.adjustTLSContext(message);
        assertEquals(context.getHttpContext().getLastRequestPath(), message.getRequestPath().getValue());
    }
}
