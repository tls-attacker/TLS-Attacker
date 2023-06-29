/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import java.io.InputStream;

public class SignedCertificateTimestampSignatureParser
        extends Parser<SignedCertificateTimestampSignature> {

    /**
     * Constructor for the Parser
     *
     * @param stream
     */
    public SignedCertificateTimestampSignatureParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SignedCertificateTimestampSignature signature) {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm =
                SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                        parseByteArrayField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHM));
        signature.setSignatureAndHashAlgorithm(signatureAndHashAlgorithm);
        int signatureLength = parseIntField(HandshakeByteLength.SIGNATURE_LENGTH);
        byte[] rawSignature = parseByteArrayField(signatureLength);
        signature.setSignature(rawSignature);
        signature.setEncodedSignature(getAlreadyParsed());
    }
}
