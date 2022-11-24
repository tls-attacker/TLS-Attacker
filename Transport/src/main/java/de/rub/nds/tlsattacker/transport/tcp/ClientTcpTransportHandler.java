/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.*;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientTcpTransportHandler extends TcpTransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    protected String hostname;
    protected long connectionTimeout;
    private boolean retryFailedSocketInitialization = false;

    public ClientTcpTransportHandler(Connection connection) {
        this(
                connection.getConnectionTimeout(),
                connection.getFirstTimeout(),
                connection.getTimeout(),
                connection.getIp(),
                connection.getPort(),
                connection.getNetworkInterface());
    }

    public ClientTcpTransportHandler(
            long firstTimeout,
            long timeout,
            String hostname,
            int port,
            NetworkInterface networkInterface) {
        this(timeout, firstTimeout, timeout, hostname, port, networkInterface);
    }

    public ClientTcpTransportHandler(long firstTimeout, long timeout, String hostname, int port) {
        this(timeout, firstTimeout, timeout, hostname, port);
    }

    public ClientTcpTransportHandler(
            long connectionTimeout,
            long firstTimeout,
            long timeout,
            String hostname,
            int serverPort,
            NetworkInterface networkInterface) {
        super(firstTimeout, timeout, ConnectionEndType.CLIENT, networkInterface);
        this.hostname = hostname;
        this.dstPort = serverPort;
        this.connectionTimeout = connectionTimeout;
        this.srcPort = null;
    }

    public ClientTcpTransportHandler(
            long connectionTimeout,
            long timeout,
            String hostname,
            int serverPort,
            int clientPort,
            NetworkInterface networkInterface) {
        super(connectionTimeout, timeout, ConnectionEndType.CLIENT, networkInterface);
        this.hostname = hostname;
        this.dstPort = serverPort;
        this.connectionTimeout = connectionTimeout;
        this.srcPort = clientPort;
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

                int srcPort = this.srcPort != null ? this.srcPort : 0;

                // resolve first IP address we can find on the specified interface
                if (networkInterface != null) {
                    Enumeration<InetAddress> interfaceAddressEnumeration =
                            networkInterface.getInetAddresses();
                    List<InetAddress> interfaceAddressList = new ArrayList<>();
                    interfaceAddressEnumeration
                            .asIterator()
                            .forEachRemaining(interfaceAddressList::add);
                    Optional<InetAddress> address =
                            interfaceAddressList.stream()
                                    // TODO: what about Ipv6 in general
                                    .filter(x -> x instanceof Inet4Address)
                                    .findFirst();
                    if (address.isEmpty()) {
                        LOGGER.warn("The specified interface does not have a usable IP address.");
                        throw new IOException();
                    }
                    socket.bind(new InetSocketAddress(address.get(), srcPort));
                } else {
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
