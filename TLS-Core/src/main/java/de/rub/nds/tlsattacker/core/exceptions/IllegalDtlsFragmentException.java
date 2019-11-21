/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.exceptions;

public class IllegalDtlsFragmentException extends RuntimeException {

    public IllegalDtlsFragmentException() {
    }

    public IllegalDtlsFragmentException(String message) {
        super(message);
    }

    public IllegalDtlsFragmentException(String message, Throwable cause) {
        super(message, cause);
    }

    public IllegalDtlsFragmentException(Throwable cause) {
        super(cause);
    }

    public IllegalDtlsFragmentException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
