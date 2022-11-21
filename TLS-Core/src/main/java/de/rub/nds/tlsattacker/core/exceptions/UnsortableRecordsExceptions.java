/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.exceptions;

public class UnsortableRecordsExceptions extends RuntimeException {

    public UnsortableRecordsExceptions() {
    }

    public UnsortableRecordsExceptions(String message) {
        super(message);
    }

    public UnsortableRecordsExceptions(String message, Throwable cause) {
        super(message, cause);
    }

    public UnsortableRecordsExceptions(Throwable cause) {
        super(cause);
    }

    public UnsortableRecordsExceptions(String message, Throwable cause, boolean enableSuppression,
        boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
