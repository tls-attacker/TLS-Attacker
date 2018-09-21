/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SessionTicketTLSExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketTlsExtensionHandler extends ExtensionHandler<SessionTicketTLSExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor
     *
     * @param context
     *            The TlsContext which the Handler should adjust
     */
    public SessionTicketTlsExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public SessionTicketTLSExtensionParser getParser(byte[] message, int pointer) {
        return new SessionTicketTLSExtensionParser(pointer, message);
    }

    @Override
    public SessionTicketTLSExtensionPreparator getPreparator(SessionTicketTLSExtensionMessage message) {
        return new SessionTicketTLSExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public SessionTicketTLSExtensionSerializer getSerializer(SessionTicketTLSExtensionMessage message) {
        return new SessionTicketTLSExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(SessionTicketTLSExtensionMessage message) {
        if (message.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SessionTLS ticket length shouldn't exceed 2 bytes as defined in RFC 4507. "
                    + "Length was " + message.getExtensionLength().getValue());
        }
        context.setSessionTicketTLS(message.getTicket().getValue());
        LOGGER.debug("The context SessionTLS ticket was set to " + ArrayConverter.bytesToHexString(message.getTicket()));
    }

}
