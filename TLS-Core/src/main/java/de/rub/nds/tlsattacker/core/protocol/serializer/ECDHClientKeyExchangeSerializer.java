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
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHClientKeyExchangeSerializer<T extends ECDHClientKeyExchangeMessage> extends
        ClientKeyExchangeSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final T msg;

    /**
     * Constructor for the ECDHClientKeyExchangerSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public ECDHClientKeyExchangeSerializer(T message, ProtocolVersion version) {
        super(message, version);
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
     * Writes the SerializedPublicKeyLength of the ECDHCLientKeyExchangeMessage
     * into the final byte[]
     */
    private void writeSerializedPublicKeyLength(T msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.ECDH_PARAM_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the ECDHCLientKeyExchangeMessage into
     * the final byte[]
     */
    private void writeSerializedPublicKey(T msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

}
