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
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SessionTicketTLSExtensionHandler extends ExtensionHandler<SessionTicketTLSExtensionMessage> {

    /**
     * Constructor
     *
     * @param context
     */
    public SessionTicketTLSExtensionHandler(TlsContext context) {
        super(context);
    }

    /**
     * Returns a new SessionTicketTLSExtensionParser
     *
     * @param message
     * @param pointer
     * @return
     */
    @Override
    public SessionTicketTLSExtensionParser getParser(byte[] message, int pointer) {
        return new SessionTicketTLSExtensionParser(pointer, message);
    }

    /**
     * Returns a new SessionTicketTLSExtensionPreparator
     *
     * @param message
     * @return
     */
    @Override
    public SessionTicketTLSExtensionPreparator getPreparator(SessionTicketTLSExtensionMessage message) {
        return new SessionTicketTLSExtensionPreparator(context, message);
    }

    /**
     * Returns a new SessionTicketTLSExtensionSerializer
     *
     * @param message
     * @return
     */
    @Override
    public SessionTicketTLSExtensionSerializer getSerializer(SessionTicketTLSExtensionMessage message) {
        return new SessionTicketTLSExtensionSerializer(message);
    }

    /**
     * Parses the content of a SessionTicketTLSExtensionMessage to the actual
     * TLSContext
     *
     * @param message
     */
    @Override
    public void adjustTLSContext(SessionTicketTLSExtensionMessage message) {
        if (message.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SessionTLS ticket length shouldn't exceed 2 bytes as defined in RFC 4507. "
                    + "Length was " + message.getExtensionLength().getValue());
        }
        context.setSessionTicketTLS(message.getTicket().getValue());
    }

}
