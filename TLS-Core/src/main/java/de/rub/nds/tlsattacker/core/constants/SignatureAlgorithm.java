/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum SignatureAlgorithm {

    ANONYMOUS,
    RSA,
    DSA,
    ECDSA,
    RSA_PSS_RSAE,
    RSA_PSS_PSS,
    ED25519,
    ED448;

    private SignatureAlgorithm() {
    }

    public String getJavaName() {
        return toString();
    }
}
