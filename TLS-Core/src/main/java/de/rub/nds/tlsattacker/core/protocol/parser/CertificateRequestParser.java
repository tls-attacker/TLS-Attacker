/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import java.io.InputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateRequestParser extends HandshakeMessageParser<CertificateRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public CertificateRequestParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(CertificateRequestMessage msg) {
        LOGGER.debug("Parsing CertificateRequestMessage");
        if (getVersion().isTLS13()) {
            parseCertificateRequestContextLength(msg);
            parseCertificateRequestContext(msg);
            parseExtensionLength(msg);
            parseExtensionBytes(msg, false);
        } else {
            parseClientCertificateTypesCount(msg);
            parseClientCertificateTypes(msg);
            if (getVersion() == ProtocolVersion.TLS12 || getVersion() == ProtocolVersion.DTLS12) {
                parseSignatureHashAlgorithmsLength(msg);
                parseSignatureHashAlgorithms(msg);
            }
            parseDistinguishedNamesLength(msg);
            if (hasDistinguishedNamesLength(msg)) {
                parseDistinguishedNames(msg);
            }
        }
    }

    /**
     * Reads the next bytes as the ClientCertificateCount and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseClientCertificateTypesCount(CertificateRequestMessage msg) {
        msg.setClientCertificateTypesCount(
                parseIntField(HandshakeByteLength.CERTIFICATES_TYPES_COUNT));
        LOGGER.debug(
                "ClientCertificateTypesCount: " + msg.getClientCertificateTypesCount().getValue());
    }

    /**
     * Reads the next bytes as the ClientCertificateTypes and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseClientCertificateTypes(CertificateRequestMessage msg) {
        msg.setClientCertificateTypes(
                parseByteArrayField(msg.getClientCertificateTypesCount().getValue()));
        LOGGER.debug(
                "ClientCertificateTypes: "
                        + Arrays.toString(msg.getClientCertificateTypes().getValue()));
    }

    /**
     * Reads the next bytes as the SignatureHashAlgorithmsLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureHashAlgorithmsLength(CertificateRequestMessage msg) {
        msg.setSignatureHashAlgorithmsLength(
                parseIntField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH));
        LOGGER.debug(
                "SignatureHashAlgorithmsLength: "
                        + msg.getSignatureHashAlgorithmsLength().getValue());
    }

    /**
     * Reads the next bytes as the SignatureHashAlgorithms and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureHashAlgorithms(CertificateRequestMessage msg) {
        msg.setSignatureHashAlgorithms(
                parseByteArrayField(msg.getSignatureHashAlgorithmsLength().getValue()));
        LOGGER.debug("SignatureHashAlgorithms: {}", msg.getSignatureHashAlgorithms().getValue());
    }

    /**
     * Reads the next bytes as the DistinguishedNamesLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseDistinguishedNamesLength(CertificateRequestMessage msg) {
        msg.setDistinguishedNamesLength(
                parseIntField(HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH));
        LOGGER.debug("DistinguishedNamesLength: " + msg.getDistinguishedNamesLength().getValue());
    }

    /**
     * Checks if the DistinguishedNamesLength has a value greater than Zero
     *
     * @param msg Message to check
     * @return True if the field has a value greater than Zero
     */
    private boolean hasDistinguishedNamesLength(CertificateRequestMessage msg) {
        return msg.getDistinguishedNamesLength().getValue() != 0;
    }

    /**
     * Reads the next bytes as the DistinguishedNames and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseDistinguishedNames(CertificateRequestMessage msg) {
        msg.setDistinguishedNames(
                parseByteArrayField(msg.getDistinguishedNamesLength().getValue()));
        LOGGER.debug("DistinguishedNames: {}", msg.getDistinguishedNames().getValue());
    }

    private void parseCertificateRequestContextLength(CertificateRequestMessage msg) {
        msg.setCertificateRequestContextLength(
                parseIntField(HandshakeByteLength.CERTIFICATE_REQUEST_CONTEXT_LENGTH));
        LOGGER.debug(
                "CertificateRequestContextLength: "
                        + msg.getCertificateRequestContextLength().getValue());
    }

    private void parseCertificateRequestContext(CertificateRequestMessage msg) {
        msg.setCertificateRequestContext(
                parseByteArrayField(msg.getCertificateRequestContextLength().getValue()));
        LOGGER.debug(
                "CertificateRequestContext: {}", msg.getCertificateRequestContext().getValue());
    }
}
