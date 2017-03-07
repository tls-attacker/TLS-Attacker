/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ProtocolMessageSerializer<T extends ProtocolMessage> extends Serializer<T> {

    public ProtocolMessageSerializer(T message) {
    }

    @Override
    protected final byte[] serializeBytes() {
        return serializeProtocolMessageContent();
    }

    public abstract byte[] serializeProtocolMessageContent();
}
