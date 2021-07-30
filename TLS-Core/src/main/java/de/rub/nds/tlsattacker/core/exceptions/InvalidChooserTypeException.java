/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.exceptions;

public class InvalidChooserTypeException extends RuntimeException {

    public InvalidChooserTypeException() {
    }

    public InvalidChooserTypeException(String message) {
        super(message);
    }

    public InvalidChooserTypeException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidChooserTypeException(Throwable cause) {
        super(cause);
    }

    public InvalidChooserTypeException(String message, Throwable cause, boolean enableSuppression,
        boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
