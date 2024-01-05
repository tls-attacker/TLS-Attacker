/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;

/**
 * @param <T> The ServerKeyExchangeMessage that should be serialized
 */
public abstract class ServerKeyExchangeSerializer<T extends ServerKeyExchangeMessage>
        extends HandshakeMessageSerializer<T> {

    protected ProtocolVersion version;

    /**
     * Constructor for the ServerKeyExchangeSerializer
     *
     * @param message Message that should be serialized
     * @param version Version of the Protocol
     */
    public ServerKeyExchangeSerializer(T message, ProtocolVersion version) {
        super(message);
        this.version = version;
    }

    protected boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    protected boolean isDTLS12() {
        return version == ProtocolVersion.DTLS12;
    }
}
