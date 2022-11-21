/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyUpdateSerializer extends HandshakeMessageSerializer<KeyUpdateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final KeyUpdateMessage msg;

    /**
     * Constructor for the FinishedMessageSerializer
     *
     * @param message
     *                Message that should be serialized
     * @param version
     *                Version of the Protocol
     */

    public KeyUpdateSerializer(KeyUpdateMessage message, ProtocolVersion version) {
        super(message, version);
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
