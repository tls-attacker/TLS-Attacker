/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
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
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 *            Type of the HandshakeMessages to serialize
 */
public abstract class HandshakeMessageSerializer<T extends HandshakeMessage> extends ProtocolMessageSerializer<T> {

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
        if (version.isDTLS()) {
            writeSequenceNumber();
            writeFragmentOffset();
            writeFragmentLength();
        }
        serializeHandshakeMessageContent();
        return getAlreadySerialized();
    }

    public abstract byte[] serializeHandshakeMessageContent();

    /**
     * Writes the SequenzNumber of the HandshakeMessage into the final byte[]
     */
    private void writeSequenceNumber() {
        appendInt(msg.getMessageSeq().getValue(), HandshakeByteLength.DTLS_MESSAGE_SEQUENCE);
        LOGGER.debug("SequenceNumber: " + msg.getMessageSeq().getValue());
    }

    /**
     * Writes the FragmentOffset of the HandshakeMessage into the final byte[]
     */
    private void writeFragmentOffset() {
        appendInt(msg.getFragmentOffset().getValue(), HandshakeByteLength.DTLS_FRAGMENT_OFFSET);
        LOGGER.debug("FragmentOffset: " + msg.getFragmentOffset().getValue());
    }

    /**
     * Writes the FragmentLength of the HandshakeMessage into the final byte[]
     */
    private void writeFragmentLength() {
        appendInt(msg.getFragmentLength().getValue(), HandshakeByteLength.DTLS_FRAGMENT_LENGTH);
        LOGGER.debug("FragmentLength: " + msg.getFragmentLength().getValue());
    }

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
