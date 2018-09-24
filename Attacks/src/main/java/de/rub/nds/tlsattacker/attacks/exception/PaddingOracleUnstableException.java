/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.exception;

/**
 *
 */
public class PaddingOracleUnstableException extends RuntimeException {

    /**
     *
     * @param string
     */
    public PaddingOracleUnstableException(String string) {
        super(string);
    }

}
