/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;

/**
 * @param <T>
 *            The ServerKeyExchangeMessage that should be serialized
 */
public abstract class ServerKeyExchangeSerializer<T extends ServerKeyExchangeMessage> extends
        HandshakeMessageSerializer<T> {

    /**
     * Constructor for the ServerKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public ServerKeyExchangeSerializer(T message, ProtocolVersion version) {
        super(message, version);
    }

}
