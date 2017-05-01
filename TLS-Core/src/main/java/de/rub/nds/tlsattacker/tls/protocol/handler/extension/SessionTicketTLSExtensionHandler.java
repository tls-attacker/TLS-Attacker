/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.SessionTicketTLSExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.SessionTicketTLSExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SessionTicketTLSExtensionHandler extends ExtensionHandler<SessionTicketTLSExtensionMessage> {

    public SessionTicketTLSExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        return new SessionTicketTLSExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(SessionTicketTLSExtensionMessage message) {
        return new SessionTicketTLSExtensionPreparator(context, message);
    }

    @Override
    public ExtensionSerializer getSerializer(SessionTicketTLSExtensionMessage message) {
        return new SessionTicketTLSExtensionSerializer(message);
    }

    @Override
    public void adjustTLSContext(SessionTicketTLSExtensionMessage message) {
        if (message.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SessionTLS ticket length shouldn't exceed 2 bytes as defined in RFC 4507. "
                    + "Length was " + message.getExtensionLength().getValue());
        }
        context.setSessionTicketTLS(message.getTicket().getValue());
    }

}
