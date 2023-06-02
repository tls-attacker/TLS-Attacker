/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
