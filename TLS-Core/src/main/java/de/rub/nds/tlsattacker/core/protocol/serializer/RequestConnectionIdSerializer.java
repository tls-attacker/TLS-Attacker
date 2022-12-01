/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.RequestConnectionIdMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RequestConnectionIdSerializer
        extends HandshakeMessageSerializer<RequestConnectionIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RequestConnectionIdSerializer(RequestConnectionIdMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing RequestConnectionId");
        writeNumCids(message);
        return getAlreadySerialized();
    }

    private void writeNumCids(RequestConnectionIdMessage message) {
        LOGGER.debug("Message: " + message);
        LOGGER.debug("numcids: " + message.getNumberOfConnectionIds());
        appendInt(
                message.getNumberOfConnectionIds().getValue(),
                HandshakeByteLength.REQUESTCONNECTIONID_NUMCID_LENGTH);
        LOGGER.debug("NumberOfConnectionIds: " + message.getNumberOfConnectionIds().getValue());
    }
}
