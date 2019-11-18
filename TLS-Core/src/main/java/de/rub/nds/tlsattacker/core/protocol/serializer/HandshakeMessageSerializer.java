/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract Serializer for HandshakeMessages
 *
 * @param <T>
 *            Type of the HandshakeMessages to serialize
 */
public abstract class HandshakeMessageSerializer<T extends HandshakeMessage> extends ProtocolMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * The message that should be serialized
     */
    private final T msg;

    /**
     * Constructor for the HandshakeMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public HandshakeMessageSerializer(T message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    /**
     * Writes the Type of the HandshakeMessage into the final byte[]
     */
    private void writeType() {
        appendByte(msg.getType().getValue());
        LOGGER.debug("Type: " + msg.getType().getValue());
    }

    /**
     * Writes the message length of the HandshakeMessage into the final byte[]
     */
    private void writeLength() {
        appendInt(msg.getLength().getValue(), HandshakeByteLength.MESSAGE_LENGTH_FIELD);
        LOGGER.debug("Length: " + msg.getLength().getValue());
    }

    @Override
    public final byte[] serializeProtocolMessageContent() {
        writeType();
        writeLength();
        serializeHandshakeMessageContent();
        return getAlreadySerialized();
    }

    public abstract byte[] serializeHandshakeMessageContent();

    /**
     * Checks if the message has an ExtensionsLength field
     *
     * @return True if the message has an ExtensionLength field
     */
    protected boolean hasExtensionLengthField() {
        return msg.getExtensionsLength() != null;
    }

    /**
     * Writes the ExtensionLength field of the message into the final byte[]
     */
    protected void writeExtensionLength() {
        appendInt(msg.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
        LOGGER.debug("ExtensionLength: " + msg.getExtensionsLength().getValue());
    }

    /**
     * Checks if the message has Extensions
     *
     * @return True if the message has Extensions
     */
    protected boolean hasExtensions() {
        return msg.getExtensionBytes() != null;
    }

    /**
     * Writes the ExtensionBytes of the message into the final byte[]
     */
    protected void writeExtensionBytes() {
        appendBytes(msg.getExtensionBytes().getValue());
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(msg.getExtensionBytes().getValue()));
    }

}
