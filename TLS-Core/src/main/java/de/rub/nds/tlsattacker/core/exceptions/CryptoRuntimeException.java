/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.exceptions;

public class CryptoRuntimeException extends RuntimeException {

    public CryptoRuntimeException() {
        super();
    }

    public CryptoRuntimeException(String message) {
        super(message);
    }

    public CryptoRuntimeException(Throwable t) {
        super(t);
    }

    public CryptoRuntimeException(String message, Throwable t) {
        super(message, t);
    }
}
