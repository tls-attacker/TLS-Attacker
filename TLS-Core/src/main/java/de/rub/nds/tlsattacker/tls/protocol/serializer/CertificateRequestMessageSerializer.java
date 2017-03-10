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
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateRequestMessageSerializer extends HandshakeMessageSerializer<CertificateRequestMessage> {

    private final CertificateRequestMessage message;

    public CertificateRequestMessageSerializer(CertificateRequestMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        appendInt(message.getClientCertificateTypesCount().getValue(), HandshakeByteLength.CERTIFICATES_TYPES_COUNT);
        appendBytes(message.getClientCertificateTypes().getValue());
        appendInt(message.getSignatureHashAlgorithmsLength().getValue(),
                HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH);
        appendBytes(message.getSignatureHashAlgorithms().getValue());
        appendInt(message.getDistinguishedNamesLength().getValue(), HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH);
        if (message.getDistinguishedNamesLength().getValue() != 0) {
            appendBytes(message.getDistinguishedNames().getValue());
        }
        return getAlreadySerialized();
    }

}
