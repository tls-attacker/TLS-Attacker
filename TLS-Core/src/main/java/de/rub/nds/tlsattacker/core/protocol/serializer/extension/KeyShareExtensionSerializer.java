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
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareExtensionSerializer extends ExtensionSerializer<KeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final KeyShareExtensionMessage msg;
    private final ConnectionEndType connection;

    public KeyShareExtensionSerializer(
            KeyShareExtensionMessage message, ConnectionEndType connection) {
        super(message);
        this.msg = message;
        this.connection = connection;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing KeyShareExtensionMessage");
        if (connection == ConnectionEndType.CLIENT && msg.getKeyShareListLength() != null) {
            writeKeyShareListLength(msg);
        }
        writeKeyShareListBytes(msg);
        return getAlreadySerialized();
    }

    private void writeKeyShareListLength(KeyShareExtensionMessage msg) {
        appendInt(
                msg.getKeyShareListLength().getValue(), ExtensionByteLength.KEY_SHARE_LIST_LENGTH);
        LOGGER.debug("KeyShareListLength: {}", msg.getKeyShareListLength().getValue());
    }

    private void writeKeyShareListBytes(KeyShareExtensionMessage msg) {
        appendBytes(msg.getKeyShareListBytes().getValue());
        LOGGER.debug("KeyShareListBytes: {}", msg.getKeyShareListBytes().getValue());
    }
}
