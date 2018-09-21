/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketTLSExtensionParser extends ExtensionParser<SessionTicketTLSExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor
     *
     * @param startposition
     *            Start of the extension in the byte array
     * @param array
     *            Array which holds the extensions
     */
    public SessionTicketTLSExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    /**
     * Parses the content of the given byte array to a
     * SessionTicketTLSExtensionMessage
     *
     * @param msg
     *            Message, which will hold the parsed extension
     */
    @Override
    public void parseExtensionMessageContent(SessionTicketTLSExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SessionTLS ticket length shouldn't exceed 2 bytes as defined in RFC 4507. "
                    + "Length was " + msg.getExtensionLength().getValue());
        }
        msg.setTicket(parseByteArrayField(msg.getExtensionLength().getValue()));
        LOGGER.debug("The session ticket TLS parser parsed the value " + bytesToHexString(msg.getTicket()));
    }

    /**
     * Creates a new SessionTicketTLSExtensionMessage
     *
     * @return An empty SessionTicketTLSExtensionMessage
     */
    @Override
    protected SessionTicketTLSExtensionMessage createExtensionMessage() {
        return new SessionTicketTLSExtensionMessage();
    }

}
