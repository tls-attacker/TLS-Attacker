/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import javax.swing.text.html.parser.DTDConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
    private final T msg;

    /**
     * Constructor for the HelloMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the protocol
     */
    public HelloMessageSerializer(T message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
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

    /**
     * Writes the ProtocolVersion of the message into the final byte[]
     */
    protected void writeProtocolVersion() {
        appendBytes(msg.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

    /**
     * Writes the UnixTime of the message into the final byte[]
     */
    protected void writeUnixtime() {
        appendBytes(msg.getUnixTime().getValue());
        LOGGER.debug("UnixTime: " + ArrayConverter.bytesToHexString(msg.getUnixTime().getValue()));
    }

    /**
     * Writes the Random of the message into the final byte[]
     */
    protected void writeRandom() {
        appendBytes(msg.getRandom().getValue());
        LOGGER.debug("Random: " + ArrayConverter.bytesToHexString(msg.getRandom().getValue()));
    }

    /**
     * Writes the SessionID length field of the message into the final byte[]
     */
    protected void writeSessionIDLength() {
        appendInt(msg.getSessionIdLength().getValue(), HandshakeByteLength.SESSION_ID_LENGTH);
        LOGGER.debug("SessionIDLength: " + msg.getSessionIdLength().getValue());
    }

    /**
     * Writes the SessionID of the message into the final byte[]
     */
    protected void writeSessionID() {
        appendBytes(msg.getSessionId().getValue());
        LOGGER.debug("SessionID: " + ArrayConverter.bytesToHexString(msg.getSessionId().getValue()));
    }
}
