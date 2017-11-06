/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;

public enum ServerCertificateKey {

    EC,
    DH,
    RSA,
    NONE;

    public static ServerCertificateKey getServerCertificateKey(CipherSuite cipherSuite) {
        String cipher = cipherSuite.toString().toUpperCase();
        if (cipher.startsWith("TLS_RSA") || cipher.matches("^TLS_[A-Z]+_RSA.+")) {
            return RSA;
        } else if (cipher.matches("^TLS_[A-Z]+_DSS.+")) {
            return DH;
        } else if (cipher.matches("^TLS_[A-Z]+_ECDSA.+")) {
            return EC;
        } else {
            return NONE;
        }
    }
}
