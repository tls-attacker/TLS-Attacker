/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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