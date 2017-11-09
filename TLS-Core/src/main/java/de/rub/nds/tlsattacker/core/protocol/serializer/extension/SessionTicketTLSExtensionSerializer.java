/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;

public class SessionTicketTLSExtensionSerializer extends ExtensionSerializer<SessionTicketTLSExtensionMessage> {

    private final SessionTicketTLSExtensionMessage message;

    /**
     * Default constructor
     * 
     * @param message
     *            A SessionTicketTLSExtensionMessage
     */
    public SessionTicketTLSExtensionSerializer(SessionTicketTLSExtensionMessage message) {
        super(message);
        this.message = message;
    }

    /**
     * Serializes the content of a SessionTicketTLSExtensionMessage
     * 
     * @return The serialized bytes of the message
     */
    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(message.getTicket().getValue());
        LOGGER.debug("Serialized PaddingExtension with SessionTicket of length "
                + message.getTicket().getValue().length);
        return getAlreadySerialized();
    }

}
