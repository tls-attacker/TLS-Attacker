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
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHClientKeyExchangeSerializer<T extends ECDHClientKeyExchangeMessage>
        extends ClientKeyExchangeSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final T msg;

    /**
     * Constructor for the ECDHClientKeyExchangerSerializer
     *
     * @param message Message that should be serialized
     */
    public ECDHClientKeyExchangeSerializer(T message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing ECDHClientKeyExchangeMessage");
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    protected byte[] serializeEcDhParams() {
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the SerializedPublicKeyLength of the ECDHClientKeyExchangeMessage into the final
     * byte[]
     */
    private void writeSerializedPublicKeyLength(T msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.ECDH_PARAM_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /** Writes the SerializedPublicKey of the ECDHClientKeyExchangeMessage into the final byte[] */
    private void writeSerializedPublicKey(T msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: {}", msg.getPublicKey().getValue());
    }
}
