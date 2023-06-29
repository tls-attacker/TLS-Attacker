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
import java.net.ServerSocket;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerTcpTransportHandler extends TcpTransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    private ServerSocket serverSocket;
    private SocketManagement socketManagement = SocketManagement.DEFAULT;

    public ServerTcpTransportHandler(Connection con) {
        super(con);
        this.srcPort = con.getPort();
    }

    public ServerTcpTransportHandler(long firstTimeout, long timeout, int port) {
        super(firstTimeout, timeout, ConnectionEndType.SERVER);
        this.srcPort = port;
    }

    public ServerTcpTransportHandler(long firstTimeout, long timeout, ServerSocket serverSocket)
            throws IOException {
        super(firstTimeout, timeout, ConnectionEndType.SERVER);
        this.srcPort = serverSocket.getLocalPort();
        this.serverSocket = serverSocket;
        socketManagement = SocketManagement.EXTERNAL_SERVER_SOCKET;
    }

    public ServerTcpTransportHandler(Connection con, Socket socket) throws IOException {
        super(con);
        this.srcPort = socket.getLocalPort();
        this.socket = socket;
        socket.setSoTimeout((int) timeout);
        socketManagement = SocketManagement.EXTERNAL_SOCKET;
    }

    public void closeServerSocket() throws IOException {
        if (serverSocket != null) {
            serverSocket.close();
        } else {
            throw new IOException("TransportHandler not initialized");
        }
    }

    @Override
    public void closeConnection() throws IOException {
        if (socket != null) {
            socket.close();
        }
        if (socketManagement == SocketManagement.DEFAULT) {
            closeServerSocket();
        }
    }

    @Override
    public void initialize() throws IOException {
        if (socketManagement != SocketManagement.EXTERNAL_SOCKET) {
            if (serverSocket == null || serverSocket.isClosed()) {
                throw new IOException("TransportHandler not preinitialized");
            }
            socket = serverSocket.accept();
            socket.setSoTimeout((int) timeout);
        }
        dstPort = socket.getPort();
        cachedSocketState = null;
        LOGGER.info("Connection established from ports {} -> {}", srcPort, dstPort);
        setStreams(new PushbackInputStream(socket.getInputStream()), socket.getOutputStream());
    }

    @Override
    public void preInitialize() throws IOException {
        if (socketManagement != SocketManagement.EXTERNAL_SOCKET) {
            if (serverSocket == null || serverSocket.isClosed()) {
                serverSocket = new ServerSocket(srcPort);
            }
            srcPort = serverSocket.getLocalPort();
        }
    }

    @Override
    public boolean isClosed() throws IOException {
        if (isInitialized()) {
            if (socket != null && (socket.isClosed() || socket.isInputShutdown())) {
                if (socketManagement != SocketManagement.DEFAULT) {
                    return true;
                } else if (serverSocket.isClosed()) {
                    return true;
                }
            } else if (socket == null) {
                if (socketManagement != SocketManagement.DEFAULT) {
                    return true;
                } else if (serverSocket.isClosed()) {
                    return true;
                }
            }
            return false;
        } else {
            throw new IOException("TransportHandler is not initialized!");
        }
    }

    public ServerSocket getServerSocket() {
        return serverSocket;
    }

    @Override
    public void closeClientConnection() throws IOException {
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
    }

    @Override
    public Integer getSrcPort() {
        if (isInitialized()) {
            return socket.getLocalPort();
        } else {
            return srcPort;
        }
    }

    @Override
    public void setSrcPort(int port) {
        if (isInitialized()) {
            throw new RuntimeException(
                    "Cannot change server port of uninitialized TransportHandler");
        } else {
            this.srcPort = port;
        }
    }

    @Override
    public Integer getDstPort() {
        if (!isInitialized()) {
            throw new RuntimeException(
                    "Cannot access client port of uninitialized TransportHandler");
        } else {
            return socket.getPort();
        }
    }

    @Override
    public void setDstPort(int port) {
        throw new RuntimeException("A ServerTransportHandler cannot set the client port");
    }

    /**
     * Defines to which extent the TransportHandler manages the socket(s) DEFAULT - manage
     * connection sockets and the ServerSocket EXTERNAL_SERVER_SOCKET - create connection sockets
     * individually but do not manage ServerSocket EXTERNAL_SOCKET - only manage a specific given
     * connection socket
     */
    private enum SocketManagement {
        DEFAULT,
        EXTERNAL_SERVER_SOCKET,
        EXTERNAL_SOCKET;
    }
}
