/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyUpdateSerializer extends HandshakeMessageSerializer<KeyUpdateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final KeyUpdateMessage msg;

    /**
     * Constructor for the FinishedMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public KeyUpdateSerializer(KeyUpdateMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing KeyUpdateMessage");
        writeKeyUpdateData(msg);
        return getAlreadySerialized();
    }

    private void writeKeyUpdateData(KeyUpdateMessage msg) {
        appendByte(msg.getRequestMode().getValue());
        LOGGER.debug("Serialized KeyUpdate Value: " + msg.getRequestMode());
    }
}
