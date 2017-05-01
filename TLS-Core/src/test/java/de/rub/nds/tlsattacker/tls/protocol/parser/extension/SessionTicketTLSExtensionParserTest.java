/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.SessionTicketTLSExtensionHandlerTest;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SessionTicketTLSExtensionMessage;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class SessionTicketTLSExtensionParserTest extends ExtensionParserTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] sessionTicket;
    private final byte[] expectedBytes;
    private final int startParsing;

    public SessionTicketTLSExtensionParserTest(ExtensionType extensionType, int extensionLength, byte[] sessionTicket,
            byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.sessionTicket = sessionTicket;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SessionTicketTLSExtensionHandlerTest.generateData();
    }

    @Override
    @Before
    public void setUp() {
        parser = new SessionTicketTLSExtensionParser(startParsing, expectedBytes);
        message = parser.parse();
    }

    @Override
    @Test
    public void testParseExtensionMessageContent() {
        assertArrayEquals(ExtensionType.SESSION_TICKET.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (int) message.getExtensionLength().getValue());
        assertArrayEquals(sessionTicket, ((SessionTicketTLSExtensionMessage) message).getTicket().getValue());
    }

}
