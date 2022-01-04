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
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class UnknownMessageParser extends ProtocolMessageParser<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolMessageType recordContentMessageType;

    private Config config;

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                                 Version of the Protocol
     * @param recordContentMessageType
     * @param config
     *                                 A Config used in the current context
     */
    public UnknownMessageParser(InputStream stream, ProtocolVersion version,
        ProtocolMessageType recordContentMessageType, Config config) {
        super(stream, config);
        this.recordContentMessageType = recordContentMessageType;
        this.config = config;
    }

    public UnknownMessageParser(InputStream stream, ProtocolVersion version, Config config) {
        super(stream, config);
        this.recordContentMessageType = ProtocolMessageType.UNKNOWN;
        this.config = config;
    }

    /**
     * Since we don't know what this is, we cannot make assumptions about length fields or the such, so we assume that
     * all data we received in the array is part of this unknown message
     */
    private void parseCompleteMessage(UnknownMessage msg) {
        msg.setCompleteResultingMessage(parseByteArrayField(getBytesLeft()));

    }

    @Override
    protected void parseMessageContent(UnknownMessage message) {
        LOGGER.debug("Parsing UnknownMessage");
        parseCompleteMessage(message);
    }

}
