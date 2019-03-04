/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

public class ClientTcpTransportHandler extends TransportHandler {

    protected Socket socket;
    protected String hostname;
    protected int port;
    protected long connectionTimeout;

    public ClientTcpTransportHandler(Connection connection) {
        super(connection.getTimeout(), ConnectionEndType.CLIENT);
        this.hostname = connection.getHostname();
        this.port = connection.getPort();
        this.connectionTimeout = 60000;
    }

    public ClientTcpTransportHandler(long timeout, String hostname, int port) {
        super(timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.port = port;
        this.connectionTimeout = timeout;
    }

    public ClientTcpTransportHandler(long connectionTimeout, long timeout, String hostname, int port) {
        super(timeout, ConnectionEndType.CLIENT);
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
        socket = new Socket();
        socket.connect(new InetSocketAddress(hostname, port), (int) connectionTimeout);
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
            socket.setSoTimeout(1);
            int read = socket.getInputStream().read();
            socket.setSoTimeout((int) timeout);
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

}
