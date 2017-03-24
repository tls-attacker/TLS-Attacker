/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An abstract Parser class for HandshakeMessages
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 *            Type of the HandshakeMessages to parse
 */
public abstract class HandshakeMessageParser<T extends HandshakeMessage> extends ProtocolMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    /**
     * The expected value for the Type field of the Message
     */
    private final HandshakeMessageType expectedType;

    private ProtocolVersion version;

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the HandshakeMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the HandshakeMessageParser is supposed to
     *            parse
     * @param expectedType
     *            The expected type of the parsed HandshakeMessage
     * @param version
     */
    public HandshakeMessageParser(int pointer, byte[] array, HandshakeMessageType expectedType, ProtocolVersion version) {
        super(pointer, array, version);
        this.expectedType = expectedType;
        this.version = version;
    }

    /**
     * Reads the next bytes as a HandshakeMessageType and writes them in the
     * message
     *
     * @param message
     *            Message to write in
     */
    private void parseType(HandshakeMessage message) {
        message.setType(parseByteField(HandshakeByteLength.MESSAGE_TYPE));
        if (message.getType().getValue() != expectedType.getValue() && expectedType != HandshakeMessageType.UNKNOWN) {
            LOGGER.warn("Parsed wrong message type. Parsed:" + message.getType().getValue() + " but expected:"
                    + expectedType.getValue());
        }
        LOGGER.debug("Type:" + message.getType().getValue());
    }

    /**
     * Reads the next bytes as the MessageLength and writes them in the message
     *
     * @param message
     *            Message to write in
     */
    private void parseLength(HandshakeMessage message) {
        message.setLength(parseIntField(HandshakeByteLength.MESSAGE_LENGTH_FIELD));
        LOGGER.debug("Length:" + message.getLength().getValue());
    }

    @Override
    protected T parseMessageContent() {
        T msg = createHandshakeMessage();
        parseType(msg);
        parseLength(msg);
        if (version.isDTLS()) {
            parseMessageSequence(msg);
            parseFragmentOffset(msg);
            parseFragmentLength(msg);
        }
        parseHandshakeMessageContent(msg);
        return msg;
    }

    protected abstract void parseHandshakeMessageContent(T msg);

    protected abstract T createHandshakeMessage();

    private void parseFragmentOffset(T msg) {
        msg.setFragmentOffset(parseIntField(HandshakeByteLength.DTLS_FRAGMENT_OFFSET));
    }

    private void parseFragmentLength(T msg) {
        msg.setFragmentLength(parseIntField(HandshakeByteLength.DTLS_FRAGMENT_LENGTH));
    }

    private void parseMessageSequence(T msg) {
        msg.setMessageSeq(parseIntField(HandshakeByteLength.DTLS_MESSAGE_SEQUENCE));
    }
}
