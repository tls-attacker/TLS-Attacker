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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientUdpTransportHandler extends UdpTransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    protected String ipv4;

    protected String ipv6;

    protected String hostname;

    protected Integer sourcePort;

    public ClientUdpTransportHandler(Connection con) {
        super(con);
        this.ipv4 = con.getIp();
        this.ipv6 = con.getIpv6();
        this.hostname = con.getHostname();
        this.port = con.getPort();
        this.sourcePort = con.getSourcePort();
    }

    public ClientUdpTransportHandler(long timeout, String ipv4, int port) {
        super(timeout, ConnectionEndType.CLIENT);
        this.ipv4 = ipv4;
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
        socket.setSoTimeout((int) timeout);
        cachedSocketState = null;
        this.initialized = true;
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }
}
