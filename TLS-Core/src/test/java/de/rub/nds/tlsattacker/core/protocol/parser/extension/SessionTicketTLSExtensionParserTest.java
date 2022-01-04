/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SessionTicketTLSExtensionParserTest {

    /**
     * Gets the test vectors of the SessionTicketTLSExtensionHandlerTest class.
     *
     * @return Collection of the parameters
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { new byte[0], new byte[0] } });
    }

    private final byte[] sessionTicket;
    private final byte[] expectedBytes;
    private SessionTicketTLSExtensionParser parser;
    private SessionTicketTLSExtensionMessage message;

    /**
     * Constructor for parameterized setup.
     *
     * @param sessionTicket
     * @param expectedBytes
     */
    public SessionTicketTLSExtensionParserTest(byte[] sessionTicket, byte[] expectedBytes) {
        this.sessionTicket = sessionTicket;
        this.expectedBytes = expectedBytes;
    }

    /**
     * Some initial setup.
     */
    @Before
    public void setUp() {
        parser = new SessionTicketTLSExtensionParser(new ByteArrayInputStream(expectedBytes), Config.createConfig());
        message = new SessionTicketTLSExtensionMessage();
    }

    /**
     * Tests the parseExtensionMessageContent method of the SessionTicketTLSExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        message = new SessionTicketTLSExtensionMessage();
        parser.parse(message);
        assertArrayEquals(sessionTicket, message.getSessionTicket().getIdentity().getValue());
    }

}
