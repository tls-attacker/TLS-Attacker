/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
