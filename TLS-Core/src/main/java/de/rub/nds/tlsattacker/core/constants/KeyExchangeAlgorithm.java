/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum KeyExchangeAlgorithm {

    NULL,
    DHE_DSS,
    DHE_RSA,
    DHE_PSK,
    DH_ANON,
    RSA,
    RSA_PSK,
    DH_DSS,
    DH_RSA,
    KRB5,
    SRP_SHA_DSS,
    SRP_SHA_RSA,
    SRP_SHA,
    PSK,
    ECDH_RSA,
    ECDH_ANON,
    ECDH_ECDSA,
    ECDHE_ECDSA,
    ECDHE_RSA,
    ECDHE_PSK,
    VKO_GOST01,
    VKO_GOST12,
    FORTEZZA_KEA,
    ECMQV_ECDSA,
    ECMQV_ECNRA,
    ECDH_ECNRA,
    CECPQ1_ECDSA;

    public boolean isEC() {
        return this.name().contains("EC");
    }

    public boolean isAnon() {
        return this.name().contains("ANON");
    }
}
