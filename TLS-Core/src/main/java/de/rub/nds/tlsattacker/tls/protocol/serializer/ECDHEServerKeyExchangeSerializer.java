/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
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
        writeCurveType(msg);
        writeNamedCurve(msg);
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        if (isTLS12() || isDTLS12()) {
            writeHashAlgorithm(msg);
            writeSignatureAlgorithm(msg);
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
        appendInt(msg.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.ECDHE_PARAM_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the ECDHEServerKeyExchangeMessage into
     * the final byte[]
     */
    private void writeSerializedPublicKey(ECDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getSerializedPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getSerializedPublicKey().getValue()));
    }

    private boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    private boolean isDTLS12() {
        return version == ProtocolVersion.DTLS12;
    }

    /**
     * Writes the HashAlgorithm of the ECDHEServerKeyExchangeMessage into the
     * final byte[]
     */
    private void writeHashAlgorithm(ECDHEServerKeyExchangeMessage msg) {
        appendByte(msg.getHashAlgorithm().getValue());
        LOGGER.debug("HashAlgorithm: " + msg.getHashAlgorithm().getValue());
    }

    /**
     * Writes the SignatureAlgorithm of the ECDHEServerKeyExchangeMessage into
     * the final byte[]
     */
    private void writeSignatureAlgorithm(ECDHEServerKeyExchangeMessage msg) {
        appendByte(msg.getSignatureAlgorithm().getValue());
        LOGGER.debug("SignatureAlgorithm: " + msg.getSignatureAlgorithm().getValue());
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
