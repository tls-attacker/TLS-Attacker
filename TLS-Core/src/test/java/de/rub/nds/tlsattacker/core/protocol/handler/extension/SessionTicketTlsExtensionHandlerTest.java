/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SessionTicketTLSExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SessionTicketTlsExtensionHandlerTest {

    private final int extensionLength = 0;
    private final byte[] sessionTicket = new byte[] { 0x00, 0x01, 0x02 };

    private TlsContext context;
    private SessionTicketTlsExtensionHandler handler;

    /**
     * Some initial set up.
     */
    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SessionTicketTlsExtensionHandler(context);
    }

    /**
     * Tests the adjustTLSContext of the SessionTicketTlsExtensionHandler class
     */
    @Test
    public void testAdjustTLSContext() {
        SessionTicketTLSExtensionMessage message = new SessionTicketTLSExtensionMessage();
        message.setTicket(sessionTicket);
        message.setExtensionLength(extensionLength);

        handler.adjustTLSContext(message);

        assertArrayEquals(sessionTicket, context.getSessionTicketTLS());
    }

    /**
     * Tests the getParser of the SessionTicketTlsExtensionHandler class
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof SessionTicketTLSExtensionParser);
    }

    /**
     * Tests the getPreparator of the SessionTicketTlsExtensionHandler class
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new SessionTicketTLSExtensionMessage()) instanceof SessionTicketTLSExtensionPreparator);
    }

    /**
     * Tests the getSerializer of the SessionTicketTlsExtensionHandler class
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new SessionTicketTLSExtensionMessage()) instanceof SessionTicketTLSExtensionSerializer);
    }

}
