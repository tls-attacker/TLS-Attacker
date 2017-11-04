/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum BulkCipherAlgorithm {

    /**
     * DESede references 3DES
     */
    NULL,
    IDEA,
    DESede,
    DES40,
    DES,
    RC4,
    RC2,
    FORTEZZA,
    CAMELLIA,
    SEED,
    ARIA,
    AES;

    public String getJavaName() {
        if (this == DES40) {
            return "DES";
        }
        return this.toString();
    }
}
