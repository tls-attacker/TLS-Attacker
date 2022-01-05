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
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageParser extends TlsMessageParser<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolMessageType recordContentMessageType;

    private Config config;

    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *                                 Position in the array where the ProtocolMessageParser is supposed to start
     *                                 parsing
     * @param array
     *                                 The byte[] which the ProtocolMessageParser is supposed to parse
     * @param version
     *                                 Version of the Protocol
     * @param recordContentMessageType
     * @param config
     *                                 A Config used in the current context
     */
    public UnknownMessageParser(int startposition, byte[] array, ProtocolVersion version,
        ProtocolMessageType recordContentMessageType, Config config) {
        super(startposition, array, version, config);
        this.recordContentMessageType = recordContentMessageType;
        this.config = config;
    }

    public UnknownMessageParser(int startposition, byte[] array, ProtocolVersion version, Config config) {
        super(startposition, array, version, config);
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
    protected UnknownMessage parseMessageContent() {
        LOGGER.debug("Parsing UnknownMessage");
        UnknownMessage msg = new UnknownMessage(config, recordContentMessageType);
        parseCompleteMessage(msg);
        return msg;
    }

}
