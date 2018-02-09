/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.exception;

public class WordlistNotFoundException extends RuntimeException {

    public WordlistNotFoundException() {
    }

    public WordlistNotFoundException(String string) {
        super(string);
    }

    public WordlistNotFoundException(String string, Throwable thrwbl) {
        super(string, thrwbl);
    }

    public WordlistNotFoundException(Throwable thrwbl) {
        super(thrwbl);
    }

    public WordlistNotFoundException(String string, Throwable thrwbl, boolean bln, boolean bln1) {
        super(string, thrwbl, bln, bln1);
    }

}
