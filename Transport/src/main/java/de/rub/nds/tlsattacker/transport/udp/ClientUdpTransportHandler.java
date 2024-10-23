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
import java.net.InetSocketAddress;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientUdpTransportHandler extends UdpTransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    protected String ipAddress;

    protected String hostname;

    protected Integer sourcePort;

    public ClientUdpTransportHandler(Connection con) {
        super(con);
        this.ipAddress = con.getIp();
        this.hostname = con.getHostname();
        this.port = con.getPort();
        this.sourcePort = con.getSourcePort();
    }

    public ClientUdpTransportHandler(long timeout, String ipAddress, int port) {
        super(timeout, ConnectionEndType.CLIENT);
        this.ipAddress = ipAddress;
        this.port = port;
    }

    @Override
    public void preInitialize() throws IOException {
        // Nothing to do here
    }

    @Override
    public void initialize() throws IOException {
        LOGGER.debug("Initializing ClientUdpTransportHandler host: {}, port: {}", hostname, port);
        if (sourcePort == null || resetClientSourcePort) {
            socket = new DatagramSocket();
        } else {
            socket = new DatagramSocket(sourcePort);
        }
        socket.connect(new InetSocketAddress(ipAddress, port));
        socket.setSoTimeout((int) timeout);
        cachedSocketState = null;
        this.initialized = true;
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }
}
