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
import de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

public class ClientTcpTransportHandler extends TcpTransportHandler {

    private static final int DEFAULT_CONNECTION_TIMEOUT_MILLISECONDS = 60000;
    protected Socket socket;
    protected String hostname;
    protected int serverPort;
    protected Integer clientPort;
    protected long connectionTimeout;

    public ClientTcpTransportHandler(Connection connection) {
        this(DEFAULT_CONNECTION_TIMEOUT_MILLISECONDS, connection.getTimeout(), connection.getIp(), connection.getPort());
    }

    public ClientTcpTransportHandler(long timeout, String hostname, int port) {
        this(DEFAULT_CONNECTION_TIMEOUT_MILLISECONDS, timeout, hostname, port);
    }

    public ClientTcpTransportHandler(long connectionTimeout, long timeout, String hostname, int serverPort) {
        super(timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.serverPort = serverPort;
        this.connectionTimeout = connectionTimeout;
        clientPort = null;
    }

    public ClientTcpTransportHandler(long connectionTimeout, long timeout, String hostname, int serverPort,
            int clientPort) {
        super(timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.serverPort = serverPort;
        this.connectionTimeout = connectionTimeout;
        this.clientPort = clientPort;
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
        socket = new Socket();
        if (clientPort != null) {
            socket.bind(new InetSocketAddress(clientPort));
        }
        socket.connect(new InetSocketAddress(hostname, serverPort), (int) connectionTimeout);
        if (!socket.isConnected()) {
            throw new IOException("Could not connect to " + hostname + ":" + "port");
        }
        setStreams(new PushbackInputStream(socket.getInputStream()), socket.getOutputStream());

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

    /**
     * Checks the current SocketState. NOTE: If you check the SocketState and
     * Data is received during the Check the current State of the
     * TransportHandler will get messed up and an Exception will be thrown.
     *
     * @return The current SocketState
     * @throws de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException
     */
    public SocketState getSocketState() throws InvalidTransportHandlerStateException {
        try {
            if (socket.getInputStream().available() > 0) {
                return SocketState.DATA_AVAILABLE;
            }
            int read = socket.getInputStream().read();
            if (read == -1) {
                return SocketState.CLOSED;
            } else {
                throw new InvalidTransportHandlerStateException("Received Data during SocketState check");
            }
        } catch (SocketTimeoutException ex) {
            return SocketState.TIMEOUT;
        } catch (SocketException ex) {
            return SocketState.SOCKET_EXCEPTION;
        } catch (IOException ex) {
            return SocketState.IO_EXCEPTION;
        }
    }

    @Override
    public Integer getServerPort() {
        return serverPort;
    }

    @Override
    public Integer getClientPort() {
        return clientPort;
    }

    @Override
    public void setServerPort(int serverPort) {
        if (isInitialized()) {
            throw new RuntimeException("Cannot change the server port once the TransportHandler is initialized");
        } else {
            this.serverPort = serverPort;
        }
    }

    @Override
    public void setClientPort(int clientPort) {
        if (isInitialized()) {
            throw new RuntimeException("Cannot change the client port once the TransportHandler is initialized");
        } else {
            this.clientPort = clientPort;
        }
    }

}
