/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.socket;

public enum SocketState {
    CLOSED,
    UP,
    DATA_AVAILABLE,
    TIMEOUT,
    SOCKET_EXCEPTION,
    IO_EXCEPTION
}
