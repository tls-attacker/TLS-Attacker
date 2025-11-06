/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.NewConnectionIdMessage;
import de.rub.nds.tlsattacker.core.protocol.message.connectionid.ConnectionId;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewConnectionIdSerializer extends HandshakeMessageSerializer<NewConnectionIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewConnectionIdSerializer(NewConnectionIdMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing NewConnectionIdMessage");
        serializeConnectionIdsLength();
        serializeConnectionIds();
        serializeUsage();
        return getAlreadySerialized();
    }

    private void serializeUsage() {
        appendByte(message.getUsage().getValue());
        LOGGER.debug("Usage: {}", message.getUsage().getValue());
    }

    private void serializeConnectionIds() {
        LOGGER.debug("ConnectionIds: ");
        for (ConnectionId connectionId : message.getConnectionIds()) {
            appendInt(
                    connectionId.getLength().getValue(), HandshakeByteLength.CONNECTION_ID_LENGTH);
            appendBytes(connectionId.getConnectionId().getValue());
            LOGGER.debug("\t - {}", connectionId.getConnectionId().getValue());
        }
    }

    private void serializeConnectionIdsLength() {
        appendInt(
                message.getConnectionIdsLength().getValue(),
                HandshakeByteLength.NEW_CONNECTION_ID_CIDS_LENGTH);
        LOGGER.debug("ConnectionIdsLength: {}", message.getConnectionIdsLength());
    }
}
