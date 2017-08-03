/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ClientTcpTransportHandler extends TransportHandler{

    private Socket socket;
    private String hostname;
    private int port;
    
    public ClientTcpTransportHandler(long timeout, String hostname, int port) {
        super(timeout);
        this.hostname = hostname;
        this.port = port;
    }

    @Override
    public void closeConnection() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void initialize() throws IOException {
        socket.connect(new InetSocketAddress(hostname, port));
    }
    
}
