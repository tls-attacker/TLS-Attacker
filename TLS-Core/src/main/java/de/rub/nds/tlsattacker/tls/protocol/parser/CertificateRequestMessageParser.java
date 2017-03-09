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

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateRequestMessageParser extends HandshakeMessageParser<CertificateRequestMessage> {

    public CertificateRequestMessageParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.CERTIFICATE_REQUEST, version);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateRequestMessage msg) {
        msg.setClientCertificateTypesCount(parseIntField(HandshakeByteLength.CERTIFICATES_TYPES_COUNT));
        msg.setClientCertificateTypes(parseByteArrayField(msg.getClientCertificateTypesCount().getValue()));
        msg.setSignatureHashAlgorithmsLength(parseIntField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH));
        msg.setSignatureHashAlgorithms(parseByteArrayField(msg.getSignatureHashAlgorithmsLength().getValue()));
        msg.setDistinguishedNamesLength(parseIntField(HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH));
        if (msg.getDistinguishedNamesLength().getValue() != 0) {
            msg.setDistinguishedNames(parseByteArrayField(msg.getDistinguishedNamesLength().getValue()));
        }
    }

    @Override
    protected CertificateRequestMessage createHandshakeMessage() {
        return new CertificateRequestMessage();
    }

}
