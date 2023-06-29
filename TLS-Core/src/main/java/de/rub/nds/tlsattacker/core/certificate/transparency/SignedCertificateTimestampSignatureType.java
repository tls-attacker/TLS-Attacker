/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.asn1.parser.ParserException;

public enum SignedCertificateTimestampSignatureType {
    CERTIFICATE_TIMESTAMP,
    TREE_HASH;

    public static SignedCertificateTimestampSignatureType decodeVersion(byte encodedVersion)
            throws ParserException {
        switch (encodedVersion) {
            case 0:
                return SignedCertificateTimestampSignatureType.CERTIFICATE_TIMESTAMP;
            case 1:
                return SignedCertificateTimestampSignatureType.TREE_HASH;
            default:
                throw new ParserException(
                        "SignedCertificateTimestampSignatureType with byte value \""
                                + encodedVersion
                                + "\" is not supported.");
        }
    }

    public static byte encodeVersion(SignedCertificateTimestampSignatureType signatureType)
            throws ParserException {
        switch (signatureType) {
            case CERTIFICATE_TIMESTAMP:
                return 0;
            case TREE_HASH:
                return 1;
            default:
                throw new ParserException("Unknown version");
        }
    }
}
