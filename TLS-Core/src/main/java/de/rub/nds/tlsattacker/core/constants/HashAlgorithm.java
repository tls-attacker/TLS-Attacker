/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

public enum HashAlgorithm {

    NONE("", 0),
    MD5("MD5", 0),
    SHA1("SHA-1", 80),
    SHA224("SHA-224", 112),
    SHA256("SHA-256", 128),
    SHA384("SHA-384", 192),
    SHA512("SHA-512", 256),
    GOSTR3411("GOST3411", 128),
    GOSTR34112012_256("GOST3411-2012-256", 128),
    GOSTR34112012_512("GOST3411-2012-512", 256);

    private final String javaName;
    /**
     * Strength according to NIST.SP.800-57pt1r5.
     *
     * @see <a href=
     *      "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf">NIST.SP.800-57pt1r5</a>
     */
    private final int securityStrength;

    HashAlgorithm(String javaName, int strength) {
        this.javaName = javaName;
        this.securityStrength = strength;
    }

    public String getJavaName() {
        return javaName;
    }

    public int getSecurityStrength() {
        return securityStrength;
    }
}
