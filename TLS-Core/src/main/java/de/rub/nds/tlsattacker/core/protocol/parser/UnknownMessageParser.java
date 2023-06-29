/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageParser extends ProtocolMessageParser<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     */
    public UnknownMessageParser(InputStream stream) {
        super(stream);
    }

    /**
     * Since we don't know what this is, we cannot make assumptions about length fields or the such,
     * so we assume that all data we received in the array is part of this unknown message
     */
    private void parseCompleteMessage(UnknownMessage msg) {
        msg.setCompleteResultingMessage(parseByteArrayField(getBytesLeft()));
    }

    @Override
    public void parse(UnknownMessage message) {
        LOGGER.debug("Parsing UnknownMessage");
        parseCompleteMessage(message);
    }
}
