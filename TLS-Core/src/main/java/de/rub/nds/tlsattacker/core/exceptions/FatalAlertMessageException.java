/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.exceptions;

/**
 * Configuration exception
 */
public class FatalAlertMessageException extends RuntimeException {

    public FatalAlertMessageException() {
        super();
    }

    public FatalAlertMessageException(String message) {
        super(message);
    }

    public FatalAlertMessageException(String message, Throwable cause) {
        super(message, cause);
    }
}
