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
import de.rub.nds.tlsattacker.tls.protocol.message.HelloMessage;

/**
 * Abstract Serializer class for HelloMessages
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 *            Type of the HelloMessage that should be serialized
 */
public abstract class HelloMessageSerializer<T extends HelloMessage> extends HandshakeMessageSerializer<T> {

    /**
     * The message that should be serialized
     */
    private final T message;

    /**
     * Constructor for the HelloMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     */
    public HelloMessageSerializer(T message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    /**
     * Checks if the message has an ExtensionsLength field
     * 
     * @return True if the message has an ExtensionLength field
     */
    protected boolean hasExtensionLengthField() {
        return message.getExtensionsLength() != null;
    }

    /**
     * Writes the ExtensionLength field of the message into the final byte[]
     */
    protected void writeExtensionLength() {
        appendInt(message.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
    }

    /**
     * Checks if the message has Extensions
     * 
     * @return True if the message has Extensions
     */
    protected boolean hasExtensions() {
        return message.getExtensionBytes() != null;
    }

    /**
     * Writes the ExtensionBytes of the message into the final byte[]
     */
    protected void writeExtensionBytes() {
        appendBytes(message.getExtensionBytes().getValue());
    }

    /**
     * Writes the ProtocolVersion of the message into the final byte[]
     */
    protected void writeProtocolVersion() {
        appendBytes(message.getProtocolVersion().getValue());
    }

    /**
     * Writes the UnixTime of the message into the final byte[]
     */
    protected void writeUnixtime() {
        appendBytes(message.getUnixTime().getValue());
    }

    /**
     * Writes the Random of the message into the final byte[]
     */
    protected void writeRandom() {
        appendBytes(message.getRandom().getValue());
    }

    /**
     * Writes the SessionID length field of the message into the final byte[]
     */
    protected void writeSessionIDLength() {
        appendInt(message.getSessionIdLength().getValue(), HandshakeByteLength.SESSION_ID_LENGTH);
    }

    /**
     * Writes the SessionID of the message into the final byte[]
     */
    protected void writeSessionID() {
        appendBytes(message.getSessionId().getValue());
    }
}
