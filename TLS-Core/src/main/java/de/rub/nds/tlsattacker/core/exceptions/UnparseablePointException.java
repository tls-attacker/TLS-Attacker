/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.exceptions;

public class UnparseablePointException extends RuntimeException {

    public UnparseablePointException() {
    }

    public UnparseablePointException(String string) {
        super(string);
    }

    public UnparseablePointException(String string, Throwable thrwbl) {
        super(string, thrwbl);
    }

    public UnparseablePointException(Throwable thrwbl) {
        super(thrwbl);
    }

    public UnparseablePointException(String string, Throwable thrwbl, boolean bln, boolean bln1) {
        super(string, thrwbl, bln, bln1);
    }
}
