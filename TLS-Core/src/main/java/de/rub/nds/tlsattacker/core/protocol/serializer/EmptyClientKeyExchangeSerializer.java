/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EmptyClientKeyExchangeSerializer<T extends EmptyClientKeyExchangeMessage>
        extends ClientKeyExchangeSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the EmptyClientKeyExchangeSerializer
     *
     * @param message Message that should be serialized
     */
    public EmptyClientKeyExchangeSerializer(T message) {
        super(message);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing EmptyClientKeyExchangeMessage");
        return getAlreadySerialized();
    }
}
