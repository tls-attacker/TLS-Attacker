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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RSAClientKeyExchangeSerializer<T extends RSAClientKeyExchangeMessage>
        extends ClientKeyExchangeSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final T msg;

    private final ProtocolVersion version;

    /**
     * Constructor for the RSAClientKeyExchangeSerializer
     *
     * @param message Message that should be serialized
     * @param version Version of the Protocol
     */
    public RSAClientKeyExchangeSerializer(T message, ProtocolVersion version) {
        super(message);
        this.msg = message;
        this.version = version;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing RSAClientKeyExchangeMessage");
        if (!version.isSSL()) {
            writeSerializedPublicKeyLength(msg);
        }
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    protected byte[] serializeRsaParams() {
        if (!version.isSSL()) {
            writeSerializedPublicKeyLength(msg);
        }
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the SerializedPublicKeyLength of the RSAClientKeyExchangeMessage into the final
     * byte[]. For RSA, PublicKeyLength actually is the length of the encrypted premaster secret.
     *
     * <p>RFC 5246 states that "the RSA-encrypted PreMasterSecret in a ClientKeyExchange is preceded
     * by two length bytes. These bytes are redundant in the case of RSA because the
     * EncryptedPreMasterSecret is the only data in the ClientKeyExchange".
     */
    private void writeSerializedPublicKeyLength(T msg) {
        appendInt(
                msg.getPublicKeyLength().getValue(),
                HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the RSAClientKeyExchangeMessage into the final byte[]. For
     * RSA, the PublicKey field actually contains the encrypted premaster secret.
     */
    private void writeSerializedPublicKey(T msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: {}", msg.getPublicKey().getValue());
    }
}
