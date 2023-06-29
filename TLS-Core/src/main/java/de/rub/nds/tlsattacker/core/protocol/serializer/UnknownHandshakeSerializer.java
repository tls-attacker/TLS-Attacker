/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownHandshakeSerializer
        extends HandshakeMessageSerializer<UnknownHandshakeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final UnknownHandshakeMessage msg;

    /**
     * Constructor for the UnknownHandshakeMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public UnknownHandshakeSerializer(UnknownHandshakeMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing UnknownHandshakeMessage");
        writeData(msg);
        return getAlreadySerialized();
    }

    /** Writes the Data of the UnknownHandshakeMessage into the final byte[] */
    private void writeData(UnknownHandshakeMessage msg) {
        appendBytes(msg.getData().getValue());
        LOGGER.debug("Data: {}", msg.getData().getValue());
    }
}
