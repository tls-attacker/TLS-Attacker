/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;

public class RSAServerKeyExchangeSerializer<T extends RSAServerKeyExchangeMessage> extends
        ServerKeyExchangeSerializer<T> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final T msg;

    public RSAServerKeyExchangeSerializer(T message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing RSAServerKeyExchangeMessage");
        writeNLength(msg);
        writeN(msg);
        writeELength(msg);
        writeE(msg);

        if (isTLS12() || isDTLS12()) {
            writeSignatureAndHashAlgorithm(msg);
        }
        writeSignatureLength(msg);
        writeSignature(msg);
        return getAlreadySerialized();
    }

    private void writeNLength(T msg) {
        appendInt(msg.getModulusLength().getValue(), HandshakeByteLength.RSA_MODULUS_LENGTH);
    }

    private void writeN(T msg) {
        appendBytes(msg.getModulus().getValue());
    }

    private void writeELength(T msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.RSA_PUBLICKEY_LENGTH);
    }

    private void writeE(T msg) {
        appendBytes(msg.getPublicKey().getValue());
    }

    /**
     * Writes the SignatureAndHashalgorithm of the DHEServerKeyExchangeMessage
     * into the final byte[]
     */
    private void writeSignatureAndHashAlgorithm(T msg) {
        appendBytes(msg.getSignatureAndHashAlgorithm().getValue());
        LOGGER.debug("SignatureAndHaslAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    private boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    private boolean isDTLS12() {
        return version == ProtocolVersion.DTLS12;
    }

    /**
     * Writes the SignatureLength of the DHEServerKeyExchangeMessage into the
     * final byte[]
     */
    private void writeSignatureLength(T msg) {
        appendInt(msg.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Writes the Signature of the DHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writeSignature(T msg) {
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

}
