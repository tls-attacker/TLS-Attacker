/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
    ED448,
    GOSTR34102001("ECGOST3410"),
    GOSTR34102012_256("ECGOST3410-2012-256"),
    GOSTR34102012_512("ECGOST3410-2012-512");

    private final String javaName;

    SignatureAlgorithm() {
        this(null);
    }

    SignatureAlgorithm(String javaName) {
        this.javaName = javaName;
    }

    public String getJavaName() {
        return javaName != null ? javaName : toString();
    }

}
