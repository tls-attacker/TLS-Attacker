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
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DHEServerKeyExchangeSerializer<T extends DHEServerKeyExchangeMessage> extends
        ServerKeyExchangeSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final T msg;

    /**
     * Constructor for the DHServerKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public DHEServerKeyExchangeSerializer(T message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing DHEServerKeyExchangeMessage");
        writePLength(msg);
        writeP(msg);
        writeGLength(msg);
        writeG(msg);
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        if (isTLS12() || isDTLS12()) {
            writeSignatureAndHashAlgorithm(msg);
        }
        writeSignatureLength(msg);
        writeSignature(msg);
        return getAlreadySerialized();
    }

    protected byte[] serializeDheParams() {
        writePLength(msg);
        writeP(msg);
        writeGLength(msg);
        writeG(msg);
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the pLength of the DHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writePLength(T msg) {
        appendInt(msg.getModulusLength().getValue(), HandshakeByteLength.DH_MODULUS_LENGTH);
        LOGGER.debug("pLength: " + msg.getModulusLength().getValue());
    }

    /**
     * Writes the P of the DHEServerKeyExchangeMessage into the final byte[]
     */
    private void writeP(T msg) {
        appendBytes(msg.getModulus().getValue());
        LOGGER.debug("P: " + ArrayConverter.bytesToHexString(msg.getModulus().getValue()));
    }

    /**
     * Writes the gLength of the DHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writeGLength(T msg) {
        appendInt(msg.getGeneratorLength().getValue(), HandshakeByteLength.DH_GENERATOR_LENGTH);
        LOGGER.debug("gLength: " + msg.getGeneratorLength().getValue());
    }

    /**
     * Writes the G of the DHEServerKeyExchangeMessage into the final byte[]
     */
    private void writeG(T msg) {
        appendBytes(msg.getGenerator().getValue());
        LOGGER.debug("G: " + ArrayConverter.bytesToHexString(msg.getGenerator().getValue()));
    }

    /**
     * Writes the SerializedPublicKeyLength of the DHEServerKeyExchangeMessage
     * into the final byte[]
     */
    private void writeSerializedPublicKeyLength(T msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the DHEServerKeyExchangeMessage into
     * the final byte[]
     */
    private void writeSerializedPublicKey(T msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
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
