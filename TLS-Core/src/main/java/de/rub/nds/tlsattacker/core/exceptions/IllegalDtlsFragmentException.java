/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
