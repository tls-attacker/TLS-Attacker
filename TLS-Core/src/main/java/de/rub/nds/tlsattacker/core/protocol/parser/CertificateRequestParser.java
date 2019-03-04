/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateRequestParser extends HandshakeMessageParser<CertificateRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the HandshakeMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the HandshakeMessageParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public CertificateRequestParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.CERTIFICATE_REQUEST, version);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateRequestMessage msg) {
        LOGGER.debug("Parsing CertificateRequestMessage");
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

    @Override
    protected CertificateRequestMessage createHandshakeMessage() {
        return new CertificateRequestMessage();
    }

    /**
     * Reads the next bytes as the ClientCertificateCount and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseClientCertificateTypesCount(CertificateRequestMessage msg) {
        msg.setClientCertificateTypesCount(parseIntField(HandshakeByteLength.CERTIFICATES_TYPES_COUNT));
        LOGGER.debug("ClientCertificateTypesCount: " + msg.getClientCertificateTypesCount().getValue());
    }

    /**
     * Reads the next bytes as the ClientCertificateTypes and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseClientCertificateTypes(CertificateRequestMessage msg) {
        msg.setClientCertificateTypes(parseByteArrayField(msg.getClientCertificateTypesCount().getValue()));
        LOGGER.debug("ClientCertificateTypes: " + Arrays.toString(msg.getClientCertificateTypes().getValue()));
    }

    /**
     * Reads the next bytes as the SignatureHashAlgorithmsLength and writes them
     * in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureHashAlgorithmsLength(CertificateRequestMessage msg) {
        msg.setSignatureHashAlgorithmsLength(parseIntField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH));
        LOGGER.debug("SignatureHashAlgorithmsLength: " + msg.getSignatureHashAlgorithmsLength().getValue());
    }

    /**
     * Reads the next bytes as the SignatureHashAlgorithms and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureHashAlgorithms(CertificateRequestMessage message) {
        message.setSignatureHashAlgorithms(parseByteArrayField(message.getSignatureHashAlgorithmsLength().getValue()));
        LOGGER.debug("SignatureHashAlgorithms: "
                + ArrayConverter.bytesToHexString(message.getSignatureHashAlgorithms().getValue()));
    }

    /**
     * Reads the next bytes as the DistinguishedNamesLength and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseDistinguishedNamesLength(CertificateRequestMessage msg) {
        msg.setDistinguishedNamesLength(parseIntField(HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH));
        LOGGER.debug("DistinguishedNamesLength: " + msg.getDistinguishedNamesLength().getValue());
    }

    /**
     * Checks if the DistinguishedNamesLength has a value greater than Zero
     *
     * @param message
     *            Message to check
     * @return True if the field has a value greater than Zero
     */
    private boolean hasDistinguishedNamesLength(CertificateRequestMessage msg) {
        return msg.getDistinguishedNamesLength().getValue() != 0;
    }

    /**
     * Reads the next bytes as the DistinguishedNames and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseDistinguishedNames(CertificateRequestMessage msg) {
        msg.setDistinguishedNames(parseByteArrayField(msg.getDistinguishedNamesLength().getValue()));
        LOGGER.debug("DistinguishedNames: " + ArrayConverter.bytesToHexString(msg.getDistinguishedNames().getValue()));

    }

}
