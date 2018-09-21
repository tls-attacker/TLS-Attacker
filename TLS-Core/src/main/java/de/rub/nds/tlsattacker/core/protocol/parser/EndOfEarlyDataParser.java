/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EndOfEarlyDataParser extends HandshakeMessageParser<EndOfEarlyDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EndOfEarlyDataParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.END_OF_EARLY_DATA, version);
    }

    @Override
    protected void parseHandshakeMessageContent(EndOfEarlyDataMessage msg) {
        LOGGER.debug("Parsing EndOfEarlyDataMessage");
        // EndOfEarlyData is always empty
    }

    @Override
    protected EndOfEarlyDataMessage createHandshakeMessage() {
        return new EndOfEarlyDataMessage();
    }

}
