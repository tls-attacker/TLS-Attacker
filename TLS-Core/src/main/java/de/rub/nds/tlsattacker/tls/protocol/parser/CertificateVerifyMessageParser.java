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
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateVerifyMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateVerifyMessageParser extends HandshakeMessageParser<CertificateVerifyMessage> {

    public CertificateVerifyMessageParser(int pointer, byte[] array, HandshakeMessageType expectedType) {
        super(pointer, array, expectedType);
    }

    @Override
    public CertificateVerifyMessage parse() {
        CertificateVerifyMessage message = new CertificateVerifyMessage();
        parseType(message);
        parseLength(message);
        message.setSignatureHashAlgorithm(parseByteArrayField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHM));
        message.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }

}
