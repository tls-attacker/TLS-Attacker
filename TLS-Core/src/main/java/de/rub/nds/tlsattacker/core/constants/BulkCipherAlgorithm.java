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
    DESede,
    RC4,
    AES;

    /**
     * @param cipherSuite
     * @return
     */
    public static BulkCipherAlgorithm getBulkCipherAlgorithm(CipherSuite cipherSuite) {
        String cipher = cipherSuite.toString().toUpperCase();
        if (cipher.contains("3DES_EDE")) {
            return DESede;
        } else if (cipher.contains("AES")) {
            return AES;
        } else if (cipher.contains("RC4")) {
            return RC4;
        } else if (cipher.contains("NULL")) {
            return NULL;
        }
        throw new UnsupportedOperationException("The cipher algorithm from " + cipherSuite + " is not supported yet.");
    }

    public String getJavaName() {
        return this.toString();
    }
}
