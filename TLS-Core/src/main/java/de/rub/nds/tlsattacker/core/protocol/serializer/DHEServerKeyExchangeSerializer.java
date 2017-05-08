/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<DHEServerKeyExchangeMessage> {

    private DHEServerKeyExchangeMessage msg;

    /**
     * Constructor for the DHServerKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public DHEServerKeyExchangeSerializer(DHEServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writePLength(msg);
        writeP(msg);
        writeGLength(msg);
        writeG(msg);
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
     * Writes the pLength of the DHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writePLength(DHEServerKeyExchangeMessage msg) {
        appendInt(msg.getpLength().getValue(), HandshakeByteLength.DH_P_LENGTH);
        LOGGER.debug("pLength: " + msg.getpLength().getValue());
    }

    /**
     * Writes the P of the DHEServerKeyExchangeMessage into the final byte[]
     */
    private void writeP(DHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getP().getValue());
        LOGGER.debug("P: " + ArrayConverter.bytesToHexString(msg.getP().getValue()));
    }

    /**
     * Writes the gLength of the DHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writeGLength(DHEServerKeyExchangeMessage msg) {
        appendInt(msg.getgLength().getValue(), HandshakeByteLength.DH_G_LENGTH);
        LOGGER.debug("gLength: " + msg.getgLength().getValue());
    }

    /**
     * Writes the G of the DHEServerKeyExchangeMessage into the final byte[]
     */
    private void writeG(DHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getG().getValue());
        LOGGER.debug("G: " + ArrayConverter.bytesToHexString(msg.getG().getValue()));
    }

    /**
     * Writes the SerializedPublicKeyLength of the DHEServerKeyExchangeMessage
     * into the final byte[]
     */
    private void writeSerializedPublicKeyLength(DHEServerKeyExchangeMessage msg) {
        appendInt(msg.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the DHEServerKeyExchangeMessage into
     * the final byte[]
     */
    private void writeSerializedPublicKey(DHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getSerializedPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getSerializedPublicKey().getValue()));
    }

    /**
     * Writes the Hashalgorithm of the DHEServerKeyExchangeMessage into the
     * final byte[]
     */
    private void writeHashAlgorithm(DHEServerKeyExchangeMessage msg) {
        appendByte(msg.getHashAlgorithm().getValue());
        LOGGER.debug("HaslAlgorithm: " + msg.getHashAlgorithm().getValue());
    }

    /**
     * Writes the SignatureAlgorithm of the DHEServerKeyExchangeMessage into the
     * final byte[]
     */
    private void writeSignatureAlgorithm(DHEServerKeyExchangeMessage msg) {
        appendByte(msg.getSignatureAlgorithm().getValue());
        LOGGER.debug("SignatureAlgorithm: " + msg.getSignatureAlgorithm().getValue());
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
    private void writeSignatureLength(DHEServerKeyExchangeMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Writes the Signature of the DHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writeSignature(DHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

}
