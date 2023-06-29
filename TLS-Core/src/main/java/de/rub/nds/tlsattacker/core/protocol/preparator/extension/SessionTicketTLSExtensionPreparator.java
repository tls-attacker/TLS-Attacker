/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketTLSExtensionPreparator
        extends ExtensionPreparator<SessionTicketTLSExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SessionTicketTLSExtensionMessage message;

    public SessionTicketTLSExtensionPreparator(
            Chooser chooser, SessionTicketTLSExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    /** Parses the content of a SessionTicketTLSExtensionMessage of the TLSContext */
    @Override
    public void prepareExtensionContent() {
        message.getSessionTicket().setIdentity(chooser.getLatestSessionTicket());
        message.getSessionTicket().setIdentityLength(chooser.getLatestSessionTicket().length);
        LOGGER.debug(
                "Prepared the SessionTicketTLSExtension with Ticket {}",
                message.getSessionTicket().getIdentity().getValue());
    }
}
