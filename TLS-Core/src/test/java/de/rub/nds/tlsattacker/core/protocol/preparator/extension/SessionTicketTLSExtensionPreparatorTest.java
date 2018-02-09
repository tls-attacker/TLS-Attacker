/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class SessionTicketTLSExtensionPreparatorTest {

    private final int extensionLength = 0;
    private final byte[] ticket = new byte[0];
    private TlsContext context;
    private SessionTicketTLSExtensionMessage message;
    private SessionTicketTLSExtensionPreparator preparator;

    /**
     * Some initial setup.
     */
    @Before
    public void setUp() {
        context = new TlsContext();
        message = new SessionTicketTLSExtensionMessage();
        preparator = new SessionTicketTLSExtensionPreparator(context.getChooser(), message,
                new SessionTicketTLSExtensionSerializer(message));
    }

    /**
     * Tests the preparator of the SessionTicketTLSExtensionPreparator.
     */
    @Test
    public void testPreparator() {
        context.getConfig().setTlsSessionTicket(ticket);
        preparator.prepare();

        assertArrayEquals(ExtensionType.SESSION_TICKET.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
        assertArrayEquals(ticket, message.getTicket().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

}
