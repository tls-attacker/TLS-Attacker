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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class HttpsRequestPreparatorTest {

    private TlsContext context;
    private HttpsRequestMessage message;
    private HttpsRequestPreparator preparator;
    private final Config config = Config.createConfig();

    @BeforeEach
    public void setUp() {
        context = new TlsContext();

        String rawMessage = "GET /index.html HTTP/1.1\r\nUser-Agent: Test\r\nHost: www.rub.de\r\n\r\n";
        HttpsRequestParser parser =
            new HttpsRequestParser(0, rawMessage.getBytes(StandardCharsets.UTF_8), ProtocolVersion.TLS12, config);
        message = parser.parse();

        preparator = new HttpsRequestPreparator(context.getChooser(), message);
    }

    @Test
    public void testPrepareProtocolMessageContents() {
        preparator.prepareProtocolMessageContents();

        assertEquals(config.getDefaultHttpsRequestPath(), message.getRequestPath().getOriginalValue());
        assertEquals("HTTP/1.1", message.getRequestProtocol().getOriginalValue());
        assertEquals("GET", message.getRequestType().getOriginalValue());
        assertEquals(2, message.getHeader().size());

    }
}
