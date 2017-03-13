/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;

/**
 * Abstract Serializer for HandshakeMessages
 * 
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 *            Type of the HandshakeMessages to serialize
 */
public abstract class HandshakeMessageSerializer<T extends HandshakeMessage> extends ProtocolMessageSerializer<T> {

    /**
     * The message that should be serialized
     */
    private final T message;

    /**
     * Constructor for the HandshakeMessageSerializer
     * 
     * @param message
     *            Message that should be serialized
     */
    public HandshakeMessageSerializer(T message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    /**
     * Writes the Type of the HandshakeMessage into the final byte[]
     */
    private void writeType() {
        appendByte(message.getType().getValue());
    }

    /**
     * Writes the message length of the HandshakeMessage into the final byte[]
     */
    private void writeLength() {
        appendInt(message.getLength().getValue(), HandshakeByteLength.MESSAGE_LENGTH_FIELD);
    }

    @Override
    public final byte[] serializeProtocolMessageContent() {
        writeType();
        writeLength();
        serializeHandshakeMessageContent();
        return getAlreadySerialized();
    }

    public abstract byte[] serializeHandshakeMessageContent();

}
