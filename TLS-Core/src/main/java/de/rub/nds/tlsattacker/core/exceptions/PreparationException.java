/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.exceptions;

public class PreparationException extends RuntimeException {

    public PreparationException() {
    }

    public PreparationException(String message) {
        super(message);
    }

    public PreparationException(String message, Throwable cause) {
        super(message, cause);
    }
}
