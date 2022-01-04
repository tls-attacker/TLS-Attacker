/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.exceptions;

public class UnknownProtocolVersionException extends RuntimeException {

    public UnknownProtocolVersionException() {
        super();
    }

    public UnknownProtocolVersionException(String message) {
        super(message);
    }

}