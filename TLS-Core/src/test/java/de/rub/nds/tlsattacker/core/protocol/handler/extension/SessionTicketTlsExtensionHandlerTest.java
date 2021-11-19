/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class SessionTicketTlsExtensionHandlerTest {

    private static final int EXTENSION_LENGTH = 0;
    private static final byte[] SESSION_TICKET = new byte[] { 0x00, 0x01, 0x02 };

    private TlsContext context;
    private SessionTicketTLSExtensionHandler handler;

    /**
     * Some initial set up.
     */
    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SessionTicketTLSExtensionHandler(context);
    }

    /**
     * Tests the adjustTLSContext of the SessionTicketTlsExtensionHandler class
     */
    @Test
    public void testAdjustTLSContext() {
        SessionTicketTLSExtensionMessage message = new SessionTicketTLSExtensionMessage();
        message.setTicket(SESSION_TICKET);
        message.setExtensionLength(EXTENSION_LENGTH);

        handler.adjustContext(message);

        assertArrayEquals(SESSION_TICKET, context.getSessionTicketTLS());
    }
}
