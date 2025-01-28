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

public class ServerUdpTransportHandler extends UdpTransportHandler {

    public ServerUdpTransportHandler(Connection con) {
        super(con);
        this.port = con.getPort();
    }

    public ServerUdpTransportHandler(long timeout, int port) {
        super(timeout, ConnectionEndType.SERVER);
        this.port = port;
    }

    @Override
    public void initialize() throws IOException {
        // this could be made an option
        if (socket == null) {
            throw new IOException("TransportHandler not preInitalized");
        } else if (socket.isClosed()) {
            // allow re-initialization
            preInitialize();
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
