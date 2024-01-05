/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;

/**
 * @param <T> The KeyExchangeMessage that should be serialized
 */
public abstract class ClientKeyExchangeSerializer<T extends ClientKeyExchangeMessage>
        extends HandshakeMessageSerializer<T> {

    /**
     * Constructor for the ClientKeyExchangeSerializer
     *
     * @param message Message that should be serialized
     */
    public ClientKeyExchangeSerializer(T message) {
        super(message);
    }
}
