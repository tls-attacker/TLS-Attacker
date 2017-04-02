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
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateRequestMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateRequestMessageSerializer extends HandshakeMessageSerializer<CertificateRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private final CertificateRequestMessage msg;

    public CertificateRequestMessageSerializer(CertificateRequestMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        serializeClientCertificateTypesCount(msg);
        serializeClientCertificateTypes(msg);
        serializeSignatureHandshakeAlgorithmsLenmgth(msg);
        serializeSignatureHandshakeAlgorithms(msg);
        serializeDistinguishedNamesLength(msg);
        if (hasDistinguishedNames(msg)) {
            serializeDistinguishedNames(msg);
        }
        return getAlreadySerialized();
    }

    private void serializeClientCertificateTypesCount(CertificateRequestMessage msg) {
        appendInt(msg.getClientCertificateTypesCount().getValue(), HandshakeByteLength.CERTIFICATES_TYPES_COUNT);
        LOGGER.debug("ClientCertificateTypesCount: "+ msg.getClientCertificateTypesCount().getValue());
    }

    private void serializeClientCertificateTypes(CertificateRequestMessage msg) {
        appendBytes(msg.getClientCertificateTypes().getValue());
        LOGGER.debug("ClientCertificateTypes: "+ Arrays.toString(msg.getClientCertificateTypes().getValue()));
    }

    private void serializeSignatureHandshakeAlgorithmsLenmgth(CertificateRequestMessage msg) {
        appendInt(msg.getSignatureHashAlgorithmsLength().getValue(),
                HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH);
        LOGGER.debug("SignatureHashAlgorithmsLength: "+ msg.getSignatureHashAlgorithmsLength().getValue());
    }

    private void serializeSignatureHandshakeAlgorithms(CertificateRequestMessage msg) {
        appendBytes(msg.getSignatureHashAlgorithms().getValue());
        LOGGER.debug("SignatureHashAlgorithms: "+ Arrays.toString(msg.getSignatureHashAlgorithms().getValue()));
    }

    private void serializeDistinguishedNamesLength(CertificateRequestMessage msg) {
        appendInt(msg.getDistinguishedNamesLength().getValue(), HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH);
        LOGGER.debug("DistinguishedNamesLength: "+ msg.getDistinguishedNamesLength().getValue());
    }

    private boolean hasDistinguishedNames(CertificateRequestMessage msg) {
        return msg.getDistinguishedNamesLength().getValue() != 0;
    }

    private void serializeDistinguishedNames(CertificateRequestMessage msg) {
        appendBytes(msg.getDistinguishedNames().getValue());
        LOGGER.debug("DistinguishedNames: "+ Arrays.toString(msg.getDistinguishedNames().getValue()));
    }

}
