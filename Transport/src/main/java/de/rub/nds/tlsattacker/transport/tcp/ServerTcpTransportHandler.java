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

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerTcpTransportHandler extends TcpTransportHandler {

    private ServerSocket serverSocket;
    private Socket socket;
    private int port;
    /**
     * If true, don't create a new ServerSocket and just use the given socket.
     * Useful for spawning server TransportHandler from an externally managed
     * ServerSocket.
     */
    private boolean externalServerSocket = false;

    public ServerTcpTransportHandler(long timeout, int port) {
        super(timeout, ConnectionEndType.SERVER);
        this.port = port;
    }

    public ServerTcpTransportHandler(long timeout, ServerSocket serverSocket) throws IOException {
        super(timeout, ConnectionEndType.SERVER);
        this.port = serverSocket.getLocalPort();
        this.serverSocket = serverSocket;
    }

    public ServerTcpTransportHandler(long timeout, Socket socket) throws IOException {
        super(timeout, ConnectionEndType.SERVER);
        this.port = socket.getLocalPort();
        this.socket = socket;
        socket.setSoTimeout(1);
        externalServerSocket = true;
    }

    public void closeServerSocket() throws IOException {
        if (serverSocket != null) {
            serverSocket.close();
        }
    }

    @Override
    public void closeConnection() throws IOException {
        if (socket != null) {
            socket.close();
        }
        if (serverSocket != null) {
            serverSocket.close();
        } else if (!externalServerSocket) {
            throw new IOException("TransportHandler not initialised");
        }
    }

    @Override
    public void initialize() throws IOException {
        if (!externalServerSocket) {
            if (serverSocket == null || serverSocket.isClosed()) {
                serverSocket = new ServerSocket(port);
            }
            socket = serverSocket.accept();
            socket.setSoTimeout(1);
        }
        setStreams(new PushbackInputStream(socket.getInputStream()), socket.getOutputStream());
    }

    @Override
    public boolean isClosed() throws IOException {
        if (isInitialized()) {
            if (socket != null && (socket.isClosed() || socket.isInputShutdown())) {
                if (externalServerSocket) {
                    return true;
                } else if (serverSocket.isClosed()) {
                    return true;
                }
            } else if (socket == null) {
                if (externalServerSocket) {
                    return true;
                } else if (serverSocket.isClosed()) {
                    return true;
                }
            }
            return false;
        } else {
            throw new IOException("Transporthandler is not initalized!");
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
    public Integer getServerPort() {
        if (!isInitialized()) {
            return serverSocket.getLocalPort();
        } else {
            return port;
        }
    }

    @Override
    public Integer getClientPort() {
        if (!isInitialized()) {
            throw new RuntimeException("Cannot access client port of uninitialized TransportHandler");
        } else {
            return socket.getPort();
        }
    }

    @Override
    public void setServerPort(int port) {
        if (isInitialized()) {
            throw new RuntimeException("Cannot change server port of uninitialized TransportHandler");
        } else {
            this.port = port;
        }
    }

    @Override
    public void setClientPort(int port) {
        throw new RuntimeException("A ServerTransportHandler cannot set the client port");
    }
}
