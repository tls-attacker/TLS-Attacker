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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class HttpsRequestPreparatorTest {

    private TlsContext context;
    private HttpsRequestMessage message;
    private HttpsRequestPreparator preparator;
    private final Config config = Config.createConfig();

    @Before
    public void setUp() {
        context = new TlsContext();

        String rawMessage = "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";
        HttpsRequestParser parser =
            new HttpsRequestParser(new ByteArrayInputStream(rawMessage.getBytes(Charset.forName("UTF-8"))));
        message = new HttpsRequestMessage();
        parser.parse(message);
        preparator = new HttpsRequestPreparator(context.getChooser(), message);
    }

    @Test
    public void testPrepareProtocolMessageContents() {
        preparator.prepareProtocolMessageContents();

        assertEquals("/", message.getRequestPath().getOriginalValue());
        assertEquals("HTTP/1.1", message.getRequestProtocol().getOriginalValue());
        assertEquals("GET", message.getRequestType().getOriginalValue());
        assertEquals(2, message.getHeader().size());

    }
}
