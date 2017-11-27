/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.exceptions;

public class ContextHandlingException extends RuntimeException {

    public ContextHandlingException() {
        super();
    }

    public ContextHandlingException(String message) {
        super(message);
    }

    public ContextHandlingException(String message, Throwable cause) {
        super(message, cause);
    }
}
