/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.udp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.SocketException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class UdpTransportHandler extends TransportHandler {

    private Logger LOGGER = LogManager.getLogger();

    protected DatagramSocket socket;

    protected int port;

    public UdpTransportHandler(Connection con) {
        super(con);
    }

    public UdpTransportHandler(long firstTimeout, long timeout, ConnectionEndType type) {
        super(firstTimeout, timeout, type);
    }

    @Override
    public void setTimeout(long timeout) {
        try {
            this.timeout = timeout;
            socket.setSoTimeout((int) timeout);
        } catch (SocketException ex) {
            LOGGER.error("Could not adjust socket timeout", ex);
        }
    }

    @Override
    public void closeConnection() throws IOException {
        socket.close();
        inStream.close();
        outStream.close();
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed();
    }

    public int getSrcPort() {
        if (socket == null) {
            // mimic socket.getLocalPort() behavior as if socket was closed
            return -1;
        }

        return socket.getLocalPort();
    }

    public int getDstPort() {
        if (socket == null) {
            // mimic socket.getPort() behavior as if socket was not connected
            return -1;
        }

        return socket.getPort();
    }
}
