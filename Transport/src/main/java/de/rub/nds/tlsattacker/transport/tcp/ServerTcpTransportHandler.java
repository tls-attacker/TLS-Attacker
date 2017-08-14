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
    private int port;

    public ServerTcpTransportHandler(long timeout, int port) {
        super(timeout, ConnectionEndType.SERVER);
        this.port = port;
    }

    @Override
    public void closeConnection() {
        try {
            socket.close();
            serverSocket.close();
        } catch (IOException ex) {
            LOGGER.error("Problem while closing sockets");
        }
    }

    @Override
    public void initialize() throws IOException {
        serverSocket = new ServerSocket(port);
        socket = serverSocket.accept();
    }

}
