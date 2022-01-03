/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketTLSExtensionParser extends ExtensionParser<SessionTicketTLSExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor
     *
     * @param stream
     * @param config
     */
    public SessionTicketTLSExtensionParser(InputStream stream, Config config) {
        super(stream, config);
    }

    /**
     * Parses the content of the given byte array to a SessionTicketTLSExtensionMessage
     *
     * @param msg
     *            Message, which will hold the parsed extension
     */
    @Override
    public void parseExtensionMessageContent(SessionTicketTLSExtensionMessage msg) {
        msg.setTicket(parseTillEnd());
        LOGGER.debug("The session ticket TLS parser parsed the value " + bytesToHexString(msg.getTicket()));
    }
}
