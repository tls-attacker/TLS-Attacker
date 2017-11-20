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
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;

/**
 * @param <T>
 *            The ProtocolMessage that should be serialized
 */
public abstract class ProtocolMessageSerializer<T extends ProtocolMessage> extends Serializer<T> {

    protected ProtocolVersion version;

    /**
     * Constructor for the ProtocolMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public ProtocolMessageSerializer(T message, ProtocolVersion version) {
        this.version = version;
    }

    @Override
    protected final byte[] serializeBytes() {
        return serializeProtocolMessageContent();
    }

    public abstract byte[] serializeProtocolMessageContent();
}
