/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientTcpTransportHandler extends TcpTransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    protected String hostname;
    protected long connectionTimeout;
    private boolean retryFailedSocketInitialization = false;

    public ClientTcpTransportHandler(Connection connection) {
        super(connection);
        this.connectionTimeout = connection.getConnectionTimeout();
        this.hostname = connection.getIp();
        this.dstPort = connection.getPort();
    }

    public ClientTcpTransportHandler(long firstTimeout, long timeout, String hostname, int port) {
        this(timeout, firstTimeout, timeout, hostname, port);
    }

    public ClientTcpTransportHandler(
            long connectionTimeout,
            long firstTimeout,
            long timeout,
            String hostname,
            int serverPort) {
        super(firstTimeout, timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.dstPort = serverPort;
        this.connectionTimeout = connectionTimeout;
        this.srcPort = null;
    }

    public ClientTcpTransportHandler(
            long connectionTimeout, long timeout, String hostname, int serverPort, int clientPort) {
        super(connectionTimeout, timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.dstPort = serverPort;
        this.connectionTimeout = connectionTimeout;
        this.srcPort = clientPort;
    }

    @Override
    public void closeConnection() throws IOException {
        if (socket == null) {
            throw new IOException("TransportHandler is not initialized!");
        }
        socket.close();
    }

    @Override
    public void preInitialize() throws IOException {
        // nothing to do here
    }

    @Override
    public void initialize() throws IOException {
        long timeoutTime = System.currentTimeMillis() + this.connectionTimeout;
        while (System.currentTimeMillis() < timeoutTime || this.connectionTimeout == 0) {
            try {
                socket = new Socket();
                socket.setReuseAddress(true);
                // reuse client port only when present and either retried socket initializations are
                // enabled or
                // client port has been manually set and the resetClientSourcePort setting is
                // disabled
                if (srcPort != null
                        && (retryFailedSocketInitialization || !resetClientSourcePort)) {
                    socket.bind(new InetSocketAddress(srcPort));
                }
                socket.connect(new InetSocketAddress(hostname, dstPort), (int) connectionTimeout);
                if (!socket.isConnected()) {
                    throw new ConnectException("Could not connect to " + hostname + ":" + dstPort);
                }
                break;
            } catch (Exception e) {
                if (!retryFailedSocketInitialization) {
                    LOGGER.warn("Socket initialization to {}:{} failed", hostname, dstPort, e);
                    break;
                }
                LOGGER.warn("Server @{}:{} is not available yet", hostname, dstPort);
                try {
                    Thread.sleep(1000);
                } catch (Exception ignore) {
                }
            }
        }

        if (!socket.isConnected()) {
            throw new IOException("Could not connect to " + hostname + ":" + dstPort);
        }
        cachedSocketState = null;
        setStreams(new PushbackInputStream(socket.getInputStream()), socket.getOutputStream());
        srcPort = socket.getLocalPort();
        dstPort = socket.getPort();
        LOGGER.info("Connection established from ports {} -> {}", srcPort, dstPort);
        socket.setSoTimeout((int) timeout);
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed() || socket.isInputShutdown();
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }

    public boolean isRetryFailedSocketInitialization() {
        return retryFailedSocketInitialization;
    }

    public void setRetryFailedSocketInitialization(boolean retryFailedSocketInitialization) {
        this.retryFailedSocketInitialization = retryFailedSocketInitialization;
    }

    @Override
    public Integer getDstPort() {
        return dstPort;
    }

    @Override
    public Integer getSrcPort() {
        return srcPort;
    }

    @Override
    public void setDstPort(int serverPort) {
        if (isInitialized()) {
            throw new RuntimeException(
                    "Cannot change the server port once the TransportHandler is initialized");
        } else {
            this.dstPort = serverPort;
        }
    }

    @Override
    public void setSrcPort(int clientPort) {
        if (isInitialized()) {
            throw new RuntimeException(
                    "Cannot change the client port once the TransportHandler is initialized");
        } else {
            this.srcPort = clientPort;
        }
    }
}
