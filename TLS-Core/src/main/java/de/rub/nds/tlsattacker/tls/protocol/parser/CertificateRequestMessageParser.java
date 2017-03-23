/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateRequestMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateRequestMessageParser extends HandshakeMessageParser<CertificateRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    public CertificateRequestMessageParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.CERTIFICATE_REQUEST, version);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateRequestMessage msg) {
        parseClientCertificateTypesCount(msg);
        parseClientCertificateTypes(msg);
        parseSignatureHashAlgorithmsLength(msg);
        parseSignatureHashAlgorithms(msg);
        parseDistinguishedNamesLength(msg);
        if (hasDistinguishedNamesLength(msg)) {
            parseDistinguishedNames(msg);
        }
    }

    @Override
    protected CertificateRequestMessage createHandshakeMessage() {
        return new CertificateRequestMessage();
    }

    private void parseClientCertificateTypesCount(CertificateRequestMessage msg) {
        msg.setClientCertificateTypesCount(parseIntField(HandshakeByteLength.CERTIFICATES_TYPES_COUNT));
        LOGGER.debug("ClientCertificateTypesCount: " + msg.getClientCertificateTypesCount().getValue());
    }

    private void parseClientCertificateTypes(CertificateRequestMessage msg) {
        msg.setClientCertificateTypes(parseByteArrayField(msg.getClientCertificateTypesCount().getValue()));
        LOGGER.debug("ClientCertificateTypes: " + Arrays.toString(msg.getClientCertificateTypes().getValue()));
    }

    private void parseSignatureHashAlgorithmsLength(CertificateRequestMessage msg) {
        msg.setSignatureHashAlgorithmsLength(parseIntField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH));
        LOGGER.debug("SignatureHashAlgorithmsLength: " + msg.getSignatureHashAlgorithmsLength().getValue());
    }

    private void parseSignatureHashAlgorithms(CertificateRequestMessage message) {
        message.setSignatureHashAlgorithms(parseByteArrayField(message.getSignatureHashAlgorithmsLength().getValue()));
        LOGGER.debug("SignatureHashAlgorithms: " + Arrays.toString(message.getSignatureHashAlgorithms().getValue()));
    }

    private void parseDistinguishedNamesLength(CertificateRequestMessage msg) {
        msg.setDistinguishedNamesLength(parseIntField(HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH));
        LOGGER.debug("DistinguishedNamesLength: " + msg.getDistinguishedNamesLength().getValue());
    }

    private boolean hasDistinguishedNamesLength(CertificateRequestMessage msg) {
        return msg.getDistinguishedNamesLength().getValue() != 0;
    }

    private void parseDistinguishedNames(CertificateRequestMessage msg) {
        msg.setDistinguishedNames(parseByteArrayField(msg.getDistinguishedNamesLength().getValue()));
        LOGGER.debug("DistinguishedNames: " + Arrays.toString(msg.getDistinguishedNames().getValue()));

    }

}
