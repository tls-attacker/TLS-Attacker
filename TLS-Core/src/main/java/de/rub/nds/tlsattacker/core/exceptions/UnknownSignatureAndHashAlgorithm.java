/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.exceptions;

public class UnknownSignatureAndHashAlgorithm extends RuntimeException {

    public UnknownSignatureAndHashAlgorithm() {}

    public UnknownSignatureAndHashAlgorithm(String message) {
        super(message);
    }

    public UnknownSignatureAndHashAlgorithm(String message, Throwable cause) {
        super(message, cause);
    }

    public UnknownSignatureAndHashAlgorithm(Throwable cause) {
        super(cause);
    }

    public UnknownSignatureAndHashAlgorithm(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
