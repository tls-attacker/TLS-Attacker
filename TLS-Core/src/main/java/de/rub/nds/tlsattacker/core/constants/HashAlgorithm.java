/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum HashAlgorithm {

    NONE(""),
    MD5("MD5"),
    SHA1("SHA-1"),
    SHA224("SHA-224"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512"),
    GOSTR3411("GOST3411"),
    GOSTR34112012_256("GOST3411-2012-256"),
    GOSTR34112012_512("GOST3411-2012-512");

    private final String javaName;

    private HashAlgorithm(String javaName) {
        this.javaName = javaName;
    }

    public String getJavaName() {
        return javaName;
    }
}
