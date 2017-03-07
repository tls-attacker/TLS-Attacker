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
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateVerifyMessageSerializer extends HandshakeMessageSerializer<CertificateVerifyMessage> {

    private final CertificateVerifyMessage message;

    public CertificateVerifyMessageSerializer(CertificateVerifyMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        appendBytes(message.getSignatureHashAlgorithm().getValue());
        appendInt(message.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        appendBytes(message.getSignature().getValue());
        return getAlreadySerialized();
    }

}
