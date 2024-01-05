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
import de.rub.nds.tlsattacker.core.protocol.message.SrpServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrpServerKeyExchangeSerializer
        extends ServerKeyExchangeSerializer<SrpServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SrpServerKeyExchangeMessage msg;

    /**
     * Constructor for the SRPServerKeyExchangeSerializer
     *
     * @param message Message that should be serialized
     * @param version Version of the Protocol
     */
    public SrpServerKeyExchangeSerializer(
            SrpServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing SRPServerKeyExchangeMessage");
        writeModulusLength(msg);
        writeModulus(msg);
        writeGeneratorLength(msg);
        writeGenerator(msg);
        writeSaltLength(msg);
        writeSalt(msg);
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        if (isTLS12() || isDTLS12()) {
            writeSignatureAndHashAlgorithm(msg);
        }
        writeSignatureLength(msg);
        writeSignature(msg);
        return getAlreadySerialized();
    }

    /** Writes the nLength of the SrpServerKeyExchangeMessage into the final byte[] */
    private void writeModulusLength(SrpServerKeyExchangeMessage msg) {
        appendInt(msg.getModulusLength().getValue(), HandshakeByteLength.SRP_MODULUS_LENGTH);
        LOGGER.debug("pLength: " + msg.getModulusLength().getValue());
    }

    /** Writes the N of the SrpServerKeyExchangeMessage into the final byte[] */
    private void writeModulus(SrpServerKeyExchangeMessage msg) {
        appendBytes(msg.getModulus().getValue());
        LOGGER.debug("P: {}", msg.getModulus().getValue());
    }

    /** Writes the saltLength of the SrpServerKeyExchangeMessage into the final byte[] */
    private void writeSaltLength(SrpServerKeyExchangeMessage msg) {
        appendInt(msg.getSaltLength().getValue(), HandshakeByteLength.SRP_SALT_LENGTH);
        LOGGER.debug("saltLength: " + msg.getSaltLength().getValue());
    }

    /** Writes the Salt of the SrpServerKeyExchangeMessage into the final byte[] */
    private void writeSalt(SrpServerKeyExchangeMessage msg) {
        appendBytes(msg.getSalt().getValue());
        LOGGER.debug("Salt: {}", msg.getSalt().getValue());
    }

    /** Writes the gLength of the SrpServerKeyExchangeMessage into the final byte[] */
    private void writeGeneratorLength(SrpServerKeyExchangeMessage msg) {
        appendInt(msg.getGeneratorLength().getValue(), HandshakeByteLength.SRP_GENERATOR_LENGTH);
        LOGGER.debug("gLength: " + msg.getGeneratorLength().getValue());
    }

    /** Writes the G of the SrpServerKeyExchangeMessage into the final byte[] */
    private void writeGenerator(SrpServerKeyExchangeMessage msg) {
        appendBytes(msg.getGenerator().getValue());
        LOGGER.debug("G: {}", msg.getGenerator().getValue());
    }

    /**
     * Writes the SerializedPublicKeyLength of the SrpServerKeyExchangeMessage into the final byte[]
     */
    private void writeSerializedPublicKeyLength(SrpServerKeyExchangeMessage msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.SRP_PUBLICKEY_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /** Writes the SerializedPublicKey of the SrpServerKeyExchangeMessage into the final byte[] */
    private void writeSerializedPublicKey(SrpServerKeyExchangeMessage msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: {}", msg.getPublicKey().getValue());
    }

    /**
     * Writes the SignatureAndHashalgorithm of the SrpServerKeyExchangeMessage into the final byte[]
     */
    private void writeSignatureAndHashAlgorithm(SrpServerKeyExchangeMessage msg) {
        appendBytes(msg.getSignatureAndHashAlgorithm().getValue());
        LOGGER.debug(
                "SignatureAndHashAlgorithm: {}", msg.getSignatureAndHashAlgorithm().getValue());
    }

    /** Writes the SignatureLength of the SrpServerKeyExchangeMessage into the final byte[] */
    private void writeSignatureLength(SrpServerKeyExchangeMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /** Writes the Signature of the SrpServerKeyExchangeMessage into the final byte[] */
    private void writeSignature(SrpServerKeyExchangeMessage msg) {
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: {}", msg.getSignature().getValue());
    }
}
