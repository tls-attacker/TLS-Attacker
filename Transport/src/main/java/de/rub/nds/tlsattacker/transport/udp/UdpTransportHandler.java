/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.udp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.socket.SocketState;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

public abstract class UdpTransportHandler extends TransportHandler {
    protected DatagramSocket socket;

    protected int port;
    protected int srcPort;
    protected int dstPort;

    public UdpTransportHandler(Connection con) {
        super(con);
    }

    public UdpTransportHandler(long firstTimeout, long timeout, ConnectionEndType type, boolean isInStreamTerminating) {
        super(firstTimeout, timeout, type, isInStreamTerminating);
    }

    public UdpTransportHandler(long firstTimeout, long timeout, ConnectionEndType type) {
        super(firstTimeout, timeout, type);
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

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }
}
