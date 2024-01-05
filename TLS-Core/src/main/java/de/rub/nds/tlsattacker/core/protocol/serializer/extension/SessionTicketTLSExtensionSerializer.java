/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketTLSExtensionSerializer
        extends ExtensionSerializer<SessionTicketTLSExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SessionTicketTLSExtensionMessage message;

    /**
     * Default constructor
     *
     * @param message A SessionTicketTLSExtensionMessage
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
        appendBytes(message.getSessionTicket().getIdentity().getValue());
        LOGGER.debug(
                "Serialized SessionTicketTLSExtension with SessionTicket of length "
                        + message.getSessionTicket().getIdentity().getValue().length);
        return getAlreadySerialized();
    }
}
