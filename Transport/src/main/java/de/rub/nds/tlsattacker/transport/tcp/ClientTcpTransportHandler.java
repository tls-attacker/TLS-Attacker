/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TcpTransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;

public class ClientTcpTransportHandler extends TcpTransportHandler {
    private static final Logger LOGGER = LogManager.getLogger();

    protected String hostname;
    protected int port;
    protected long connectionTimeout;

    public ClientTcpTransportHandler(Connection connection) {
        this(connection.getConnectionTimeout(), connection.getFirstTimeout(), connection.getTimeout(), connection
                .getIp(), connection.getPort());
    }

    public ClientTcpTransportHandler(long firstTimeout, long timeout, String hostname, int port) {
        this(timeout, firstTimeout, timeout, hostname, port);
    }

    public ClientTcpTransportHandler(long connectionTimeout, long firstTimeout, long timeout, String hostname, int port) {
        super(firstTimeout, timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.port = port;
        this.connectionTimeout = connectionTimeout;
    }

    @Override
    public void closeConnection() throws IOException {
        if (socket == null) {
            throw new IOException("Transporthandler is not initalized!");
        }
        socket.close();
    }

    @Override
    public void initialize() throws IOException {
        long timeoutTime = System.currentTimeMillis() + this.connectionTimeout;
        while (System.currentTimeMillis() < timeoutTime || this.connectionTimeout == 0) {
            try {
                socket = new Socket();
                socket.connect(new InetSocketAddress(hostname, port), (int) connectionTimeout);
                if (!socket.isConnected()) {
                    throw new ConnectException("Could not connect to " + hostname + ":" + port);
                }
                break;
            } catch (Exception e) {
                LOGGER.warn("Server @" + hostname + ":" + port + " is not available yet");
                try {
                    Thread.sleep(1000);
                } catch (Exception ignore) {
                }
            }
        }

        if (!socket.isConnected()) {
            throw new IOException("Could not connect to " + hostname + ":" + "port");
        }
        setStreams(new PushbackInputStream(socket.getInputStream()), socket.getOutputStream());
        srcPort = socket.getLocalPort();
        dstPort = socket.getPort();
        socket.setSoTimeout(1);
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed() || socket.isInputShutdown();
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }

}
