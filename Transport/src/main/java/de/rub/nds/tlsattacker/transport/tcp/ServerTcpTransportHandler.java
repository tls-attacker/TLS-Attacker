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
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ServerTcpTransportHandler extends TransportHandler {

    private ServerSocket serverSocket;
    private Socket socket;
    private final int port;

    public ServerTcpTransportHandler(long timeout, int port) {
        super(timeout, ConnectionEndType.SERVER);
        this.port = port;
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

}
