/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.modifiablevariable.util.ArrayConverter;

public enum SignedCertificateTimestampEntryType {
    X509ChainEntry,
    PrecertChainEntry;

    public static SignedCertificateTimestampEntryType decodeVersion(byte[] encodedVersion) throws ParserException {
        int encoded = ArrayConverter.bytesToInt(encodedVersion);
        switch (encoded) {
            case 0:
                return SignedCertificateTimestampEntryType.X509ChainEntry;
            case 1:
                return SignedCertificateTimestampEntryType.PrecertChainEntry;
            default:
                throw new ParserException(
                    "SignedCertificateTimestampEntryType with byte value \"" + encoded + "\" is not supported.");
        }
    }

    public static byte[] encodeVersion(SignedCertificateTimestampEntryType entryType) throws ParserException {
        switch (entryType) {
            case X509ChainEntry:
                return ArrayConverter.intToBytes(0, 2);
            case PrecertChainEntry:
                return ArrayConverter.intToBytes(1, 2);
            default:
                throw new ParserException("Unknown version");
        }
    }
}
