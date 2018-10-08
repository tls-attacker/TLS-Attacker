/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

/**
 * @version 0.1
 */
public class OracleException extends RuntimeException {

    /**
     *
     */
    public OracleException() {

    }

    /**
     *
     * @param message
     */
    public OracleException(String message) {
        super(message);
    }

    /**
     *
     * @param message
     * @param t
     */
    public OracleException(String message, Throwable t) {
        super(message, t);
    }

}
