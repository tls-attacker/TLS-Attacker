/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.util;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.SocketException;

/**
 * This small Helper tries to find an empty server port. Sometimes staring a server socket on port 0
 * is not an option
 */
public class FreePortFinder {
    /**
     * This method tries to find a free TCP port. Note that there is a small timeframe in which the
     * port could be allocated by another Thread/Service
     *
     * @return
     */
    public static int getPossiblyFreeTcpPort() {
        try {
            int port;
            try (ServerSocket socket = new ServerSocket(0)) {
                port = socket.getLocalPort();
            }
            return port;
        } catch (IOException ex) {
            throw new RuntimeException("Could not find a free TCP port");
        }
    }

    /**
     * This method tries to find a free UDP port. Note that there is a small timeframe in which the
     * port could be allocated by another Thread/Service
     *
     * @return
     */
    public static int getPossiblyFreeUdpPort() {
        try {
            int port;
            try (DatagramSocket socket = new DatagramSocket(0)) {
                port = socket.getLocalPort();
            }
            return port;
        } catch (IOException ex) {
            throw new RuntimeException("Could not find a free UDP port");
        }
    }

    /**
     * Returns a ServerSocket bound to a free TCP port. The caller is responsible for closing the
     * socket. This avoids the TOCTOU race of {@link #getPossiblyFreeTcpPort()}.
     *
     * @return a ServerSocket bound to a free port
     */
    public static ServerSocket getFreeTcpSocket() {
        try {
            return new ServerSocket(0);
        } catch (IOException ex) {
            throw new RuntimeException("Could not find a free TCP port");
        }
    }

    /**
     * Returns a DatagramSocket bound to a free UDP port. The caller is responsible for closing the
     * socket. This avoids the TOCTOU race of {@link #getPossiblyFreeUdpPort()}.
     *
     * @return a DatagramSocket bound to a free port
     */
    public static DatagramSocket getFreeUdpSocket() {
        try {
            return new DatagramSocket(0);
        } catch (SocketException ex) {
            throw new RuntimeException("Could not find a free UDP port");
        }
    }

    private FreePortFinder() {}
}
