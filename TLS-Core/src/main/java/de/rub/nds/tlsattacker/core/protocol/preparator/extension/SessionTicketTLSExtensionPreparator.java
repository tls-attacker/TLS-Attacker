/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SessionTicketTLSExtensionPreparator extends ExtensionPreparator<SessionTicketTLSExtensionMessage> {

    private final SessionTicketTLSExtensionMessage message;

    /**
     * 
     * @param context
     *            A TLSContext
     * @param message
     *            A SessionTicketTLSExtensionMessage
     */
    public SessionTicketTLSExtensionPreparator(Chooser chooser, SessionTicketTLSExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    /**
     * Parses the content of a SessionTicketTLSExtensionMessage of the
     * TLSContext
     */
    @Override
    public void prepareExtensionContent() {
        message.setTicket(chooser.getConfig().getTLSSessionTicket());
        LOGGER.debug("Prepared the SessionTicketTLSExtension with Ticket "
                + ArrayConverter.bytesToHexString(message.getTicket().getValue()));
    }

}
