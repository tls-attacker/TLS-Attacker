/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.parser.SessionTicketParser;
import java.io.InputStream;

public class SessionTicketTLSExtensionParser
        extends ExtensionParser<SessionTicketTLSExtensionMessage> {

    private final byte[] configTicketKeyName;
    private final CipherAlgorithm configCipherAlgorithm;
    private final MacAlgorithm configMacAlgorithm;

    /**
     * Constructor
     *
     * @param stream
     * @param config
     */
    public SessionTicketTLSExtensionParser(
            InputStream stream, Config config, TlsContext tlsContext) {
        super(stream, tlsContext);
        configTicketKeyName = config.getSessionTicketKeyName();
        configCipherAlgorithm = config.getSessionTicketCipherAlgorithm();
        configMacAlgorithm = config.getSessionTicketMacAlgorithm();
    }

    /**
     * Parses the content of the given byte array to a SessionTicketTLSExtensionMessage
     *
     * @param msg Message, which will hold the parsed extension
     */
    @Override
    public void parse(SessionTicketTLSExtensionMessage msg) {
        SessionTicket ticket = new SessionTicket();
        msg.setSessionTicket(ticket);
        // only parse if the extension indicates data
        if (getBytesLeft() > 0) {
            SessionTicketParser ticketParser =
                    new SessionTicketParser(
                            0,
                            msg.getExtensionContent().getValue(),
                            msg.getSessionTicket(),
                            configTicketKeyName,
                            configCipherAlgorithm,
                            configMacAlgorithm);
            ticketParser.parse(ticket);
        }
    }
}
