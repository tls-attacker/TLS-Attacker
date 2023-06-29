/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract Serializer for HandshakeMessages
 *
 * @param <T> Type of the HandshakeMessages to serialize
 */
public abstract class HandshakeMessageSerializer<T extends HandshakeMessage>
        extends ProtocolMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the HandshakeMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public HandshakeMessageSerializer(T message) {
        super(message);
    }

    /** Writes the Type of the HandshakeMessage into the final byte[] */
    protected void writeType() {
        appendByte(message.getType().getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }

    /** Writes the message length of the HandshakeMessage into the final byte[] */
    protected void writeLength() {
        appendInt(message.getLength().getValue(), HandshakeByteLength.MESSAGE_LENGTH_FIELD);
        LOGGER.debug("Length: " + message.getLength().getValue());
    }

    private void writeContent() {
        appendBytes(message.getMessageContent().getValue());
        LOGGER.debug("HandshakeMessage content: {}", message.getMessageContent().getValue());
    }

    @Override
    protected byte[] serializeBytes() {
        writeType();
        writeLength();
        writeContent();
        return getAlreadySerialized();
    }

    public abstract byte[] serializeHandshakeMessageContent();

    /**
     * Checks if the message has an ExtensionsLength field
     *
     * @return True if the message has an ExtensionLength field
     */
    protected boolean hasExtensionLengthField() {
        return message.getExtensionsLength() != null;
    }

    /** Writes the ExtensionLength field of the message into the final byte[] */
    protected void writeExtensionLength() {
        appendInt(message.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
        LOGGER.debug("ExtensionLength: " + message.getExtensionsLength().getValue());
    }

    /**
     * Checks if the message has Extensions
     *
     * @return True if the message has Extensions
     */
    protected boolean hasExtensions() {
        return message.getExtensionBytes() != null;
    }

    /** Writes the ExtensionBytes of the message into the final byte[] */
    protected void writeExtensionBytes() {
        appendBytes(message.getExtensionBytes().getValue());
        LOGGER.debug("ExtensionBytes: {}", message.getExtensionBytes().getValue());
    }
}
