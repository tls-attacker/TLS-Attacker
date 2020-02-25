/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.exceptions;

public class TransportHandlerConnectException extends RuntimeException {

    public TransportHandlerConnectException() {
    }

    public TransportHandlerConnectException(String string) {
        super(string);
    }

    public TransportHandlerConnectException(String string, Throwable thrwbl) {
        super(string, thrwbl);
    }

    public TransportHandlerConnectException(Throwable thrwbl) {
        super(thrwbl);
    }

    public TransportHandlerConnectException(String string, Throwable thrwbl, boolean bln, boolean bln1) {
        super(string, thrwbl, bln, bln1);
    }
}
