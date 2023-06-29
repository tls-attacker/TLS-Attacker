/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ConnectionIdExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionIdExtensionSerializer
        extends ExtensionSerializer<ConnectionIdExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConnectionIdExtensionMessage message;

    public ConnectionIdExtensionSerializer(ConnectionIdExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing ConnectionIdExtensionMessage");
        serializeConnectionIdLength(message);
        serializeConnectionId(message);
        return getAlreadySerialized();
    }

    private void serializeConnectionIdLength(ConnectionIdExtensionMessage msg) {
        appendInt(msg.getConnectionIdLength().getValue(), ExtensionByteLength.CONNECTION_ID_LENGTH);
        LOGGER.debug("ConnectionId length: " + msg.getConnectionIdLength().getValue());
    }

    private void serializeConnectionId(ConnectionIdExtensionMessage msg) {
        appendBytes(msg.getConnectionId().getValue());
        LOGGER.debug("ConnectionId: {}", msg.getConnectionId().getValue());
    }
}
