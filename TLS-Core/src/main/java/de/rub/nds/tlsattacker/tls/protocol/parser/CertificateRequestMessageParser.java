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
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateRequestMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateRequestMessageParser extends HandshakeMessageParser<CertificateRequestMessage> {

    public CertificateRequestMessageParser(int pointer, byte[] array) {
        super(pointer, array, HandshakeMessageType.CERTIFICATE_REQUEST);
    }

    @Override
    public CertificateRequestMessage parse() {
        CertificateRequestMessage message = new CertificateRequestMessage();
        parseType(message);
        parseLength(message);
        message.setClientCertificateTypesCount(parseIntField(HandshakeByteLength.CERTIFICATES_TYPES_COUNT));
        message.setClientCertificateTypes(parseByteArrayField(message.getClientCertificateTypesCount().getValue()));
        message.setSignatureHashAlgorithmsLength(parseIntField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH));
        message.setSignatureHashAlgorithms(parseByteArrayField(message.getSignatureHashAlgorithmsLength().getValue()));
        message.setDistinguishedNamesLength(parseIntField(HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH));
        message.setDistinguishedNames(parseByteArrayField(message.getDistinguishedNamesLength().getValue()));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }

}
