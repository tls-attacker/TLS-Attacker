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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ClientTcpTransportHandler extends TransportHandler {

    private Socket socket;
    private String hostname;
    private int port;

    public ClientTcpTransportHandler(long timeout, String hostname, int port) {
        super(timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.port = port;
    }

    @Override
    public void closeConnection() {
        try {
            socket.close();
        } catch (IOException ex) {
            LOGGER.error("Problem while closing the socket", ex);
        }
    }

    @Override
    public void initialize() throws IOException {
        socket = new Socket(hostname, port);

        setStreams(socket.getInputStream(), socket.getOutputStream());
    }

}
