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

public enum SignedCertificateTimestampVersion {
    V1;

    public static SignedCertificateTimestampVersion decodeVersion(byte encodedVersion)
            throws ParserException {
        switch (encodedVersion) {
            case (byte) 0:
                return SignedCertificateTimestampVersion.V1;
            default:
                throw new ParserException(
                        "SignedCertificateTimestampVersion with byte value \""
                                + encodedVersion
                                + "\" is not supported.");
        }
    }

    public static byte encodeVersion(SignedCertificateTimestampVersion version)
            throws ParserException {
        switch (version) {
            case V1:
                return 0;
            default:
                throw new ParserException("Unknown version");
        }
    }
}
