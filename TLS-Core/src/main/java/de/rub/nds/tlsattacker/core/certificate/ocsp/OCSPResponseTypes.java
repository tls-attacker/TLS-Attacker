/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

public enum OCSPResponseTypes {
    BASIC("1.3.6.1.5.5.7.48.1.1"),
    NONCE("1.3.6.1.5.5.7.48.1.2"),
    CRL_REFERENCES("1.3.6.1.5.5.7.48.1.3"),
    ACCEPTABLE_RESPONSES("1.3.6.1.5.5.7.48.1.4"),
    NO_CHECK("1.3.6.1.5.5.7.48.1.5"),
    ARCHIVE_CUTOFF("1.3.6.1.5.5.7.48.1.6"),
    SERVICE_LOCATOR("1.3.6.1.5.5.7.48.1.7"),
    PREFERRED_SIGNATURE_ALGORITHMS("1.3.6.1.5.5.7.48.1.8"),
    EXTENDED_REVOKED("1.3.6.1.5.5.7.48.1.9");

    private final String extension;

    /**
     * @param extension
     */

    OCSPResponseTypes(final String extension) {
        this.extension = extension;
    }

    public String getOID() {
        return extension;
    }
}
