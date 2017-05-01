/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import com.sun.media.jfxmedia.logging.Logger;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SessionTicketTLSExtensionPreparator extends ExtensionPreparator<SessionTicketTLSExtensionMessage> {

    private final SessionTicketTLSExtensionMessage message;

    public SessionTicketTLSExtensionPreparator(TlsContext context, SessionTicketTLSExtensionMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        message.setTicket(context.getConfig().getSessionTLSTicket());
        LOGGER.debug("Prepared the SessionTicketTLSExtension with Ticket "
                + ArrayConverter.bytesToHexString(message.getTicket().getValue()));
    }

}
