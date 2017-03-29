/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.exception;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnloadableConfigException extends RuntimeException {

    public UnloadableConfigException() {
    }

    public UnloadableConfigException(String message) {
        super(message);
    }

    public UnloadableConfigException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnloadableConfigException(Throwable cause) {
        super(cause);
    }

    public UnloadableConfigException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
