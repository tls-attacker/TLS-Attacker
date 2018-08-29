/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum DigestAlgorithm {

    SSL_DIGEST(""),
    LEGACY(""),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    GOSTR3411("GOST3411"),
    GOSTR34112012_256("GOST3411-2012-256");

    private DigestAlgorithm(String digestAlgorithm) {
        this.javaName = digestAlgorithm;
    }

    private final String javaName;

    public String getJavaName() {
        return javaName;
    }
}
