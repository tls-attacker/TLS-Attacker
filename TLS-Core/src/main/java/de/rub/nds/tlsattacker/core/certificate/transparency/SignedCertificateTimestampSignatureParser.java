/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.Parser;

public class SignedCertificateTimestampSignatureParser extends Parser<SignedCertificateTimestampSignature> {

    /**
     * Constructor for the Parser
     *
     * @param startposition
     *                         Position in the array from which the Parser should start working
     * @param encodedSignature
     */
    public SignedCertificateTimestampSignatureParser(int startposition, byte[] encodedSignature) {
        super(startposition, encodedSignature);
    }

    @Override
    public SignedCertificateTimestampSignature parse() {
        SignedCertificateTimestampSignature signature = new SignedCertificateTimestampSignature();

        SignatureAndHashAlgorithm signatureAndHashAlgorithm = SignatureAndHashAlgorithm
            .getSignatureAndHashAlgorithm(parseByteArrayField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHM));
        signature.setSignatureAndHashAlgorithm(signatureAndHashAlgorithm);

        int signatureLength = parseIntField(HandshakeByteLength.SIGNATURE_LENGTH);

        byte[] rawSignature = parseByteArrayField(signatureLength);
        signature.setSignature(rawSignature);

        signature.setEncodedSignature(getAlreadyParsed());

        return signature;
    }
}
