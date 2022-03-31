/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class AlertParser extends ProtocolMessageParser<AlertMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                Version of the Protocol
     * @param config
     *                A Config used in the current context
     */
    public AlertParser(InputStream stream, ProtocolVersion version, Config config) {
        super(stream, config);
    }

    @Override
    public void parse(AlertMessage message) {
        LOGGER.debug("Parsing AlertMessage");
        parseLevel(message);
        parseDescription(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
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
