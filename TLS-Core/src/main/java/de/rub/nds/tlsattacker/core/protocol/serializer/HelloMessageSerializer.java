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
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract Serializer class for HelloMessages
 *
 * @param <T> Type of the HelloMessage that should be serialized
 */
public abstract class HelloMessageSerializer<T extends HelloMessage>
        extends HandshakeMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /** The message that should be serialized */
    private final T msg;

    /**
     * Constructor for the HelloMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public HelloMessageSerializer(T message) {
        super(message);
        this.msg = message;
    }

    /** Writes the ProtocolVersion of the message into the final byte[] */
    protected void writeProtocolVersion() {
        appendBytes(msg.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: {}", msg.getProtocolVersion().getValue());
    }

    /** Writes the Random of the message into the final byte[] */
    protected void writeRandom() {
        appendBytes(msg.getRandom().getValue());
        LOGGER.debug("Random: {}", msg.getRandom().getValue());
    }

    /** Writes the SessionID length field of the message into the final byte[] */
    protected void writeSessionIDLength() {
        appendInt(msg.getSessionIdLength().getValue(), HandshakeByteLength.SESSION_ID_LENGTH);
        LOGGER.debug("SessionIDLength: {}", msg.getSessionIdLength().getValue());
    }

    /** Writes the SessionID of the message into the final byte[] */
    protected void writeSessionID() {
        appendBytes(msg.getSessionId().getValue());
        LOGGER.debug("SessionID: {}", msg.getSessionId().getValue());
    }
}
