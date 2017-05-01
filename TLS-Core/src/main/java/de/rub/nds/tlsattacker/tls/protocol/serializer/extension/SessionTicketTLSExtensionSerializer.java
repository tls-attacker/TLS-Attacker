/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.SessionTicketTLSExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SessionTicketTLSExtensionSerializer extends ExtensionSerializer<SessionTicketTLSExtensionMessage> {

    private final SessionTicketTLSExtensionMessage message;

    public SessionTicketTLSExtensionSerializer(SessionTicketTLSExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(message.getTicket().getValue());
        LOGGER.debug("Serialized PaddingExtension with SessionTicket of length "
                + message.getTicket().getValue().length);
        return getAlreadySerialized();
    }

}
