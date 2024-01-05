/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerHelloDoneSerializer extends HandshakeMessageSerializer<ServerHelloDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerHelloDoneMessage msg;

    /**
     * Constructor for the ServerHelloDoneSerializer
     *
     * @param message Message that should be serialized
     */
    public ServerHelloDoneSerializer(ServerHelloDoneMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing ServerHelloDoneMessage");
        return getAlreadySerialized();
    }
}
