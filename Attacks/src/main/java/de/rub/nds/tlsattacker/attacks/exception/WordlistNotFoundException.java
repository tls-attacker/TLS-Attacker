/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.attacks.exception;

/**
 *
 */
public class WordlistNotFoundException extends RuntimeException {

    /**
     *
     */
    public WordlistNotFoundException() {
    }

    /**
     *
     * @param string
     */
    public WordlistNotFoundException(String string) {
        super(string);
    }

    /**
     *
     * @param string
     * @param throwable
     */
    public WordlistNotFoundException(String string, Throwable throwable) {
        super(string, throwable);
    }

    /**
     *
     * @param throwable
     */
    public WordlistNotFoundException(Throwable throwable) {
        super(throwable);
    }

    /**
     *
     * @param string
     * @param throwable
     * @param bln
     * @param bln1
     */
    public WordlistNotFoundException(String string, Throwable throwable, boolean bln, boolean bln1) {
        super(string, throwable, bln, bln1);
    }

}
