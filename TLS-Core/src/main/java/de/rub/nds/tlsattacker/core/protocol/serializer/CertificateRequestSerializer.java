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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateRequestSerializer
        extends HandshakeMessageSerializer<CertificateRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificateRequestMessage msg;

    private final ProtocolVersion version;

    /**
     * Constructor for the CertificateRequestSerializer
     *
     * @param message Message that should be serialized
     * @param version Version of the Protocol
     */
    public CertificateRequestSerializer(
            CertificateRequestMessage message, ProtocolVersion version) {
        super(message);
        this.msg = message;
        this.version = version;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing CertificateRequestMessage");
        if (version.is13()) {
            writeCertificateRequestContextLength(msg);
            writeCertificateRequestContext(msg);
            writeExtensionLength();
            writeExtensionBytes();
        } else {
            writeClientCertificateTypesCount(msg);
            writeClientCertificateTypes(msg);
            if (version == ProtocolVersion.TLS12 || version == ProtocolVersion.DTLS12) {
                writeSignatureHandshakeAlgorithmsLength(msg);
                writeSignatureHandshakeAlgorithms(msg);
            }
            writeDistinguishedNamesLength(msg);
            if (hasDistinguishedNames(msg)) {
                writeDistinguishedNames(msg);
            }
        }

        return getAlreadySerialized();
    }

    /**
     * Writes the ClientCertificateTypeCount of the CertificateRequestMessage into the final byte[]
     */
    private void writeClientCertificateTypesCount(CertificateRequestMessage msg) {
        appendInt(
                msg.getClientCertificateTypesCount().getValue(),
                HandshakeByteLength.CERTIFICATES_TYPES_COUNT);
        LOGGER.debug(
                "ClientCertificateTypesCount: {}", msg.getClientCertificateTypesCount().getValue());
    }

    /** Writes the ClientCertificateType of the CertificateRequestMessage into the final byte[] */
    private void writeClientCertificateTypes(CertificateRequestMessage msg) {
        appendBytes(msg.getClientCertificateTypes().getValue());
        LOGGER.debug("ClientCertificateTypes: {}", msg.getClientCertificateTypes().getValue());
    }

    /**
     * Writes the SignatureHandshakeAlgorithmsLength of the CertificateRequestMessage into the final
     * byte[]
     */
    private void writeSignatureHandshakeAlgorithmsLength(CertificateRequestMessage msg) {
        appendInt(
                msg.getSignatureHashAlgorithmsLength().getValue(),
                HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH);
        LOGGER.debug(
                "SignatureHashAlgorithmsLength: {}",
                msg.getSignatureHashAlgorithmsLength().getValue());
    }

    /**
     * Writes the SignatureHandshakeAlgorithms of the CertificateRequestMessage into the final
     * byte[]
     */
    private void writeSignatureHandshakeAlgorithms(CertificateRequestMessage msg) {
        appendBytes(msg.getSignatureHashAlgorithms().getValue());
        LOGGER.debug("SignatureHashAlgorithms: {}", msg.getSignatureHashAlgorithms().getValue());
    }

    /**
     * Writes the DistinguishedNamesLength of the CertificateRequestMessage into the final byte[]
     */
    private void writeDistinguishedNamesLength(CertificateRequestMessage msg) {
        appendInt(
                msg.getDistinguishedNamesLength().getValue(),
                HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH);
        LOGGER.debug("DistinguishedNamesLength: {}", msg.getDistinguishedNamesLength().getValue());
    }

    private boolean hasDistinguishedNames(CertificateRequestMessage msg) {
        return msg.getDistinguishedNamesLength().getValue() != 0;
    }

    /** Writes the DistinguishedNames of the CertificateRequestMessage into the final byte[] */
    private void writeDistinguishedNames(CertificateRequestMessage msg) {
        appendBytes(msg.getDistinguishedNames().getValue());
        LOGGER.debug("DistinguishedNames: {}", msg.getDistinguishedNames().getValue());
    }

    private void writeCertificateRequestContext(CertificateRequestMessage msg) {
        appendBytes(msg.getCertificateRequestContext().getValue());
        LOGGER.debug(
                "CertificateRequestContext: {}", msg.getCertificateRequestContext().getValue());
    }

    private void writeCertificateRequestContextLength(CertificateRequestMessage msg) {
        appendInt(
                msg.getCertificateRequestContextLength().getValue(),
                HandshakeByteLength.CERTIFICATE_REQUEST_CONTEXT_LENGTH);
        LOGGER.debug(
                "CertificateRequestContextLength: {}",
                msg.getCertificateRequestContextLength().getValue());
    }
}
