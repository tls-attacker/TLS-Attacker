/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.socket;

public enum SocketState {
    CLOSED,
    PEER_WRITE_CLOSED,
    UP,
    DATA_AVAILABLE,
    TIMEOUT,
    SOCKET_EXCEPTION,
    IO_EXCEPTION,
    UNAVAILABLE
}
