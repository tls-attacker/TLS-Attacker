/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class HttpsRequestHandlerTest {

    private TlsContext context;
    private HttpsRequestMessage message;
    private HttpsRequestHandler handler;
    private final Config config = Config.createConfig();

    @Before
    public void setUp() {
        context = new TlsContext();

        String rawMessage = "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";
        HttpsRequestParser parser = new HttpsRequestParser(
            new ByteArrayInputStream(rawMessage.getBytes(Charset.forName("UTF-8"))), ProtocolVersion.TLS12, config);
        message = new HttpsRequestMessage();
        parser.parse(message);

        handler = new HttpsRequestHandler(context);
    }

    @Test
    public void testadjustContext() {
        handler.adjustContext(message);
        assertEquals(context.getHttpContext().getLastRequestPath(), message.getRequestPath().getValue());
    }
}
