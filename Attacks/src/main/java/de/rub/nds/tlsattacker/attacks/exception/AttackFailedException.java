/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.exception;

/**
 *
 * @author robert
 */
public class AttackFailedException extends RuntimeException {

    public AttackFailedException() {
    }

    public AttackFailedException(String message) {
        super(message);
    }

    public AttackFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public AttackFailedException(Throwable cause) {
        super(cause);
    }

    public AttackFailedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
