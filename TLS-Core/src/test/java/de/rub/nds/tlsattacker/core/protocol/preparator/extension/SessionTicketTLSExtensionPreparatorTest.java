/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import org.junit.jupiter.api.Test;

public class SessionTicketTLSExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                SessionTicketTLSExtensionMessage,
                SessionTicketTLSExtensionSerializer,
                SessionTicketTLSExtensionPreparator> {

    public SessionTicketTLSExtensionPreparatorTest() {
        super(
                SessionTicketTLSExtensionMessage::new,
                SessionTicketTLSExtensionSerializer::new,
                SessionTicketTLSExtensionPreparator::new);
    }

    /** Tests the preparator of the SessionTicketTLSExtensionPreparator. */
    @Test
    @Override
    public void testPrepare() {
        byte[] ticket = new byte[] {1, 2, 3, 4};
        TicketSession session = new TicketSession(new byte[] {1, 1, 1, 1}, ticket);
        context.addNewSession(session);
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.SESSION_TICKET.getValue(), message.getExtensionType().getValue());
        assertEquals(4, message.getExtensionLength().getValue());
        assertArrayEquals(ticket, message.getSessionTicket().getIdentity().getValue());
    }
}
