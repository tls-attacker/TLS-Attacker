/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.exceptions;

public class UnparseablePointException extends RuntimeException {

    public UnparseablePointException() {
    }

    public UnparseablePointException(String string) {
        super(string);
    }

    public UnparseablePointException(String string, Throwable throwable) {
        super(string, throwable);
    }

    public UnparseablePointException(Throwable throwable) {
        super(throwable);
    }

    public UnparseablePointException(String string, Throwable throwable, boolean bln, boolean bln1) {
        super(string, throwable, bln, bln1);
    }
}
