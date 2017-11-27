/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerTcpTransportHandler extends TransportHandler {

    private ServerSocket serverSocket;
    private Socket socket;
    private final int port;

    public ServerTcpTransportHandler(long timeout, int port) {
        super(timeout, ConnectionEndType.SERVER);
        this.port = port;
    }

    public ServerTcpTransportHandler(long timeout, ServerSocket serverSocket) throws IOException {
        super(timeout, ConnectionEndType.SERVER);
        this.port = serverSocket.getLocalPort();
        this.serverSocket = serverSocket;
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
        } else {
            throw new IOException("TransportHandler not initialised");
        }
    }

    @Override
    public void initialize() throws IOException {
        if (serverSocket == null || serverSocket.isClosed()) {
            serverSocket = new ServerSocket(port);
        }
        socket = serverSocket.accept();
        setStreams(socket.getInputStream(), socket.getOutputStream());
    }

    @Override
    public boolean isClosed() throws IOException {
        if (isInitialized()) {
            if (socket != null && (socket.isClosed() || socket.isInputShutdown())) {
                if (serverSocket.isClosed()) {
                    return true;
                }
            } else if (socket == null && serverSocket.isClosed()) {
                return true;
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

    public int getPort() {
        if (serverSocket != null) {
            return serverSocket.getLocalPort();
        } else {
            return port;
        }
    }
}
