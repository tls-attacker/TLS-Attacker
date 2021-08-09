/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.nonblocking;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerTCPNonBlockingTransportHandler extends TcpTransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    private int serverPort;

    private ServerSocket serverSocket;

    private AcceptorCallable callable;

    private FutureTask<Socket> task;

    private Thread thread;

    private boolean initialized = false;

    public ServerTCPNonBlockingTransportHandler(long firstTimeout, long timeout, int serverPort) {
        super(firstTimeout, timeout, ConnectionEndType.SERVER);
        this.serverPort = serverPort;
    }

    public ServerTCPNonBlockingTransportHandler(Connection con) {
        super(con);
        this.serverPort = con.getPort();
    }

    @Override
    public void closeConnection() throws IOException {
        if (serverSocket != null) {
            serverSocket.close();
        }
        if (socket != null) {
            socket.close();
        }
    }

    @Override
    public void initialize() throws IOException {
        serverSocket = new ServerSocket(serverPort);
        callable = new AcceptorCallable(serverSocket);
        task = new FutureTask(callable);
        thread = new Thread(task);
        thread.start();
        cachedSocketState = null;
        isInitialized();
    }

    @Override
    public boolean isInitialized() {
        if (initialized) {
            return initialized;
        }
        if (task != null) {
            if (task.isDone()) {
                try {
                    socket = task.get();
                    socket.setSoTimeout(1);
                    setStreams(new PushbackInputStream(socket.getInputStream()), socket.getOutputStream());
                    initialized = true;
                    return true;
                } catch (IOException | InterruptedException | ExecutionException ex) {
                    LOGGER.warn("Could not retrieve clientSocket");
                    LOGGER.debug(ex);
                    return false;
                }
            } else {
                LOGGER.debug("TransportHandler not yet connected");
                return false;
            }
        } else {
            return false;
        }
    }

    @Override
    public boolean isClosed() throws IOException {
        if (isInitialized()) {
            if (socket != null && socket.isClosed()) {
                if (serverSocket.isClosed()) {
                    return true;
                } else if (socket == null && serverSocket.isClosed()) {
                    return true;
                }
            }
            return false;
        } else {
            throw new IOException("TransportHandler is not initialized!");
        }
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
            return serverPort;
        }
    }

    @Override
    public Integer getSrcPort() {
        if (!isInitialized()) {
            return serverSocket.getLocalPort();
        } else {
            return serverPort;
        }
    }

    @Override
    public Integer getDstPort() {
        if (!isInitialized()) {
            throw new RuntimeException("Cannot access client port of uninitialized TransportHandler");
        } else {
            return socket.getPort();
        }
    }

    @Override
    public void setSrcPort(int port) {
        if (isInitialized()) {
            throw new RuntimeException("Cannot change server port of uninitialized TransportHandler");
        } else {
            this.serverPort = port;
        }
    }

    @Override
    public void setDstPort(int port) {
        throw new RuntimeException("A ServerTransportHandler cannot set the client port");
    }
}
