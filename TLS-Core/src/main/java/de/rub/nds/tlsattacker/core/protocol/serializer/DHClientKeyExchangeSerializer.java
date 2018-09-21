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
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DHClientKeyExchangeSerializer<T extends DHClientKeyExchangeMessage> extends ClientKeyExchangeSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T msg;

    /**
     * Constructor for the DHClientKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public DHClientKeyExchangeSerializer(T message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing DHClientKeyExchangeMessage");
        return serializeDhParams();
    }

    protected byte[] serializeDhParams() {
        // Contrary to what the SSLv3 RFC states, the message also includes the
        // DH public key length
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the SerializedPublicKeyLength of the DHClientKeyExchangeMessage
     * into the final byte[]
     */
    private void writeSerializedPublicKeyLength(T msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH);
        LOGGER.debug("SerializedPublicKexLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the DHClientKeyExchangeMessage into the
     * final byte[]
     */
    private void writeSerializedPublicKey(T msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }
}
