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
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.SocketException;

public class ServerUdpTransportHandler extends UdpTransportHandler {

    public ServerUdpTransportHandler(Connection con) {
        super(con);
        this.port = con.getPort();
    }

    public ServerUdpTransportHandler(long firstTimeout, long timeout, int port) {
        super(firstTimeout, timeout, ConnectionEndType.SERVER);
        this.port = port;
    }

    public ServerUdpTransportHandler(long firstTimeout, long timeout, DatagramSocket socket) {
        super(firstTimeout, timeout, ConnectionEndType.SERVER);
        this.socket = socket;
        try {
            socket.setSoTimeout((int) timeout);
        } catch (SocketException e) {
            throw new RuntimeException("Could not set socket timeout", e);
        }
        setStreams(
                new PushbackInputStream(new UdpInputStream(socket, true)),
                new UdpOutputStream(socket));
        cachedSocketState = null;
    }

    @Override
    public void initialize() throws IOException {
        // this could be made an option
        if (socket == null) {
            throw new IOException("TransportHandler not preInitalized");
        }
        this.initialized = true;
    }

    @Override
    public void preInitialize() throws IOException {
        socket = new DatagramSocket(port);
        cachedSocketState = null;
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }
}
