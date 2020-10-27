/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;

import java.util.Arrays;

public class SignedCertificateTimestampSignatureParser {

    public static SignedCertificateTimestampSignature parseSignature(byte[] encodedSignature) {
        SignedCertificateTimestampSignature signature = new SignedCertificateTimestampSignature();
        signature.setEncodedSignature(encodedSignature);

        SignatureAndHashAlgorithm signatureAndHashAlgorithm = SignatureAndHashAlgorithm
                .getSignatureAndHashAlgorithm(Arrays.copyOfRange(encodedSignature, 0, 2));
        signature.setSignatureAndHashAlgorithm(signatureAndHashAlgorithm);

        // Use index value to navigate through variable-length encoded signature
        int index = 2;

        int signatureLength = encodedSignature[index] << 8 | encodedSignature[index + 1] & 0x00ff;
        index += 2;

        byte[] rawSignature = Arrays.copyOfRange(encodedSignature, index, index + signatureLength);
        signature.setSignature(rawSignature);

        return signature;
    }

}
