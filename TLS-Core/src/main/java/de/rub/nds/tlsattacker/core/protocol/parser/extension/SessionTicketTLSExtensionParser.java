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
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.parser.SessionTicketParser;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketTLSExtensionParser extends ExtensionParser<SessionTicketTLSExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final byte[] configTicketKeyName;
    private final CipherAlgorithm configCipherAlgorithm;
    private final MacAlgorithm configMacAlgorithm;

    /**
     * Constructor
     *
     * @param startposition
     *                      Start of the extension in the byte array
     * @param array
     *                      Array which holds the extensions
     */
    public SessionTicketTLSExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
        configTicketKeyName = config.getSessionTicketKeyName();
        configCipherAlgorithm = config.getSessionTicketCipherAlgorithm();
        configMacAlgorithm = config.getSessionTicketMacAlgorithm();
    }

    /**
     * Parses the content of the given byte array to a SessionTicketTLSExtensionMessage
     *
     * @param msg
     *            Message, which will hold the parsed extension
     */
    @Override
    public void parseExtensionMessageContent(SessionTicketTLSExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SessionTLS ticket length shouldn't exceed 2 bytes as defined in RFC 4507. " + "Length was "
                + msg.getExtensionLength().getValue());
        }
        if (msg.getExtensionLength().getValue() > 0) {
            LOGGER.debug("Parsing session ticket as resumption offer");
            msg.getSessionTicket().setIdentityLength(msg.getExtensionLength().getValue());
            msg.getSessionTicket()
                .setIdentity(parseByteArrayField(msg.getSessionTicket().getIdentityLength().getValue()));
            SessionTicketParser ticketParser =
                new SessionTicketParser(0, msg.getSessionTicket().getIdentity().getValue(), msg.getSessionTicket(),
                    configTicketKeyName, configCipherAlgorithm, configMacAlgorithm);
            ticketParser.parse();
        } else {
            LOGGER.debug("Parsing extension as indication for ticket support");
            msg.getSessionTicket().setIdentity(new byte[0]);
            msg.getSessionTicket().setIdentityLength(0);
            LOGGER.debug("Parsed session ticket identity " + bytesToHexString(msg.getSessionTicket().getIdentity()));
        }
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
