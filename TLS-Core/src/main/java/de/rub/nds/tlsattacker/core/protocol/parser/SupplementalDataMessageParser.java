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
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;

/**
 * @author Christoph Penkert <christoph.penkert@rub.de>
 */

// todo Implement SupplementalDataMessageParser
public class SupplementalDataMessageParser<T extends SupplementalDataMessage> extends HandshakeMessageParser<T> {
    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the HandshakeMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the HandshakeMessageParser is supposed to
     *            parse
     * @param version
     */
    public SupplementalDataMessageParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SUPPLEMENTAL_DATA, version);
    }

    @Override
    protected void parseHandshakeMessageContent(SupplementalDataMessage msg) {
        LOGGER.debug("Parsing SupplementalDataMessage");
        throw new UnsupportedOperationException("Not Implemented");
    }

    @Override
    protected T createHandshakeMessage() {
        throw new UnsupportedOperationException("Not Implemented");
    }
}
