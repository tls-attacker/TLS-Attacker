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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateRequestMessageSerializer extends HandshakeMessageSerializer<CertificateRequestMessage> {

    private final CertificateRequestMessage msg;

    /**
     * Constructor for the CertificateRequestSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public CertificateRequestMessageSerializer(CertificateRequestMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeClientCertificateTypesCount(msg);
        writeClientCertificateTypes(msg);
        writeSignatureHandshakeAlgorithmsLength(msg);
        writeSignatureHandshakeAlgorithms(msg);
        writeDistinguishedNamesLength(msg);
        if (hasDistinguishedNames(msg)) {
            writeDistinguishedNames(msg);
        }
        return getAlreadySerialized();
    }

    /**
     * Writes the ClientCertificateTypeCount of the CertificateRequestMessage
     * into the final byte[]
     */
    private void writeClientCertificateTypesCount(CertificateRequestMessage msg) {
        appendInt(msg.getClientCertificateTypesCount().getValue(), HandshakeByteLength.CERTIFICATES_TYPES_COUNT);
        LOGGER.debug("ClientCertificateTypesCount: " + msg.getClientCertificateTypesCount().getValue());
    }

    /**
     * Writes the ClientCertificateType of the CertificateRequestMessage into
     * the final byte[]
     */
    private void writeClientCertificateTypes(CertificateRequestMessage msg) {
        appendBytes(msg.getClientCertificateTypes().getValue());
        LOGGER.debug("ClientCertificateTypes: "
                + ArrayConverter.bytesToHexString(msg.getClientCertificateTypes().getValue()));
    }

    /**
     * Writes the SignatureHandshakeAlgorithmsLength of the
     * CertificateRequestMessage into the final byte[]
     */
    private void writeSignatureHandshakeAlgorithmsLength(CertificateRequestMessage msg) {
        appendInt(msg.getSignatureHashAlgorithmsLength().getValue(),
                HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH);
        LOGGER.debug("SignatureHashAlgorithmsLength: " + msg.getSignatureHashAlgorithmsLength().getValue());
    }

    /**
     * Writes the SignatureHandshakeAlgorithms of the CertificateRequestMessage
     * into the final byte[]
     */
    private void writeSignatureHandshakeAlgorithms(CertificateRequestMessage msg) {
        appendBytes(msg.getSignatureHashAlgorithms().getValue());
        LOGGER.debug("SignatureHashAlgorithms: "
                + ArrayConverter.bytesToHexString(msg.getSignatureHashAlgorithms().getValue()));
    }

    /**
     * Writes the DiestinguishedNamesLength of the CertificateRequestMessage
     * into the final byte[]
     */
    private void writeDistinguishedNamesLength(CertificateRequestMessage msg) {
        appendInt(msg.getDistinguishedNamesLength().getValue(), HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH);
        LOGGER.debug("DistinguishedNamesLength: " + msg.getDistinguishedNamesLength().getValue());
    }

    private boolean hasDistinguishedNames(CertificateRequestMessage msg) {
        return msg.getDistinguishedNamesLength().getValue() != 0;
    }

    /**
     * Writes the DistinguishedNames of the CertificateRequestMessage into the
     * final byte[]
     */
    private void writeDistinguishedNames(CertificateRequestMessage msg) {
        appendBytes(msg.getDistinguishedNames().getValue());
        LOGGER.debug("DistinguishedNames: " + ArrayConverter.bytesToHexString(msg.getDistinguishedNames().getValue()));
    }

}
