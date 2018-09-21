/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownParser extends ProtocolMessageParser<UnknownMessage> {

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
    public UnknownParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    /**
     * Since we dont know what this is, we cannot make assumptions about length
     * fields or the such, so we assume that all data we received in the array
     * is part of this unknown message
     */
    private void parseCompleteMessage(UnknownMessage msg) {
        parseByteArrayField(getBytesLeft());
    }

    @Override
    protected UnknownMessage parseMessageContent() {
        LOGGER.debug("Parsing UnknownMessage");
        UnknownMessage msg = new UnknownMessage();
        parseCompleteMessage(msg);
        return msg;
    }

}
