/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

/**
 *
 *
 */
public enum CertificateKeyType {
    DH,
    ECDH,
    RSA,
    DSA,
    ECDH_ECDSA,
    GOST01,
    GOST12,
    FORTEZZA,
    ECNRA,
    ED25519,
    ED448,
    X25519,
    X448,
    NONE;
}
