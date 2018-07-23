/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.exceptions;

public class UnknownSignatureAndHashAlgorithm extends RuntimeException {

    public UnknownSignatureAndHashAlgorithm() {
    }

    public UnknownSignatureAndHashAlgorithm(String message) {
        super(message);
    }

    public UnknownSignatureAndHashAlgorithm(String message, Throwable cause) {
        super(message, cause);
    }

    public UnknownSignatureAndHashAlgorithm(Throwable cause) {
        super(cause);
    }

    public UnknownSignatureAndHashAlgorithm(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
