/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.AlertByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlertParser extends ProtocolMessageParser<AlertMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *            Position in the array where the ProtocolMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ProtocolMessageParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public AlertParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected AlertMessage parseMessageContent() {
        LOGGER.debug("Parsing AlertMessage");
        AlertMessage msg = new AlertMessage();
        parseLevel(msg);
        parseDescription(msg);
        return msg;
    }

    /**
     * Reads the next bytes as the Level and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseLevel(AlertMessage msg) {
        msg.setLevel(parseByteField(AlertByteLength.LEVEL_LENGTH));
        LOGGER.debug("Level: " + msg.getLevel().getValue());
    }

    /**
     * Reads the next bytes as a Description and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseDescription(AlertMessage msg) {
        msg.setDescription(parseByteField(AlertByteLength.DESCRIPTION_LENGTH));
        LOGGER.debug("Description: " + msg.getDescription().getValue());
    }
}
