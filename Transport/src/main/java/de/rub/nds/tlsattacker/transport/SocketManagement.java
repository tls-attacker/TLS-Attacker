/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport;

/**
 * Defines to which extent the TransportHandler manages the socket(s). DEFAULT - manage connection
 * sockets and the server socket. EXTERNAL_SERVER_SOCKET - create connection sockets individually
 * but do not manage the server socket. EXTERNAL_SOCKET - only manage a specific given connection
 * socket.
 */
public enum SocketManagement {
    DEFAULT,
    EXTERNAL_SERVER_SOCKET,
    EXTERNAL_SOCKET;
}
