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
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;

/**
 *

 */
public class ECDHEServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<ECDHEServerKeyExchangeMessage> {

    private final ECDHEServerKeyExchangeMessage msg;

    /**
     * Constructor for the ECDHServerKeyExchangerSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public ECDHEServerKeyExchangeSerializer(ECDHEServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing ECDHEServerKeyExchangeMessage");
        writeCurveType(msg);
        writeNamedCurve(msg);
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        if (isTLS12() || isDTLS12()) {
            writeSignatureAndHashAlgorithm(msg);
        }
        writeSignatureLength(msg);
        writeSignature(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the CurveType of the ECDHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writeCurveType(ECDHEServerKeyExchangeMessage msg) {
        appendByte(msg.getCurveType().getValue());
        LOGGER.debug("CurveType: " + msg.getCurveType().getValue());
    }

    /**
     * Writes the NamedCurve of the ECDHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writeNamedCurve(ECDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getNamedCurve().getValue());
        LOGGER.debug("NamedCurve: " + ArrayConverter.bytesToHexString(msg.getNamedCurve().getValue()));
    }

    /**
     * Writes the SerializedPublicKeyLength of the ECDHEServerKeyExchangeMessage
     * into the final byte[]
     */
    private void writeSerializedPublicKeyLength(ECDHEServerKeyExchangeMessage msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.ECDHE_PARAM_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the ECDHEServerKeyExchangeMessage into
     * the final byte[]
     */
    private void writeSerializedPublicKey(ECDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    private boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    private boolean isDTLS12() {
        return version == ProtocolVersion.DTLS12;
    }

    /**
     * Writes the SignatureAndHashAlgorithm of the ECDHEServerKeyExchangeMessage
     * into the final byte[]
     */
    private void writeSignatureAndHashAlgorithm(ECDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getSignatureAndHashAlgorithm().getValue());
        LOGGER.debug("SignatureAndHaslAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    /**
     * Writes the SignatureLength of the ECDHEServerKeyExchangeMessage into the
     * final byte[]
     */
    private void writeSignatureLength(ECDHEServerKeyExchangeMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Writes the Signature of the ECDHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writeSignature(ECDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

}
