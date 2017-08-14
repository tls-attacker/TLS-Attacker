/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.nonblocking;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ServerTCPNonBlockingTransportHandler extends TransportHandler {

    private SocketChannel accept;

    private ServerSocketChannel serverSocketChannel;
    
    private int port;

    public ServerTCPNonBlockingTransportHandler(long timeout, int port) {
        super(timeout, ConnectionEndType.SERVER);
        this.port = port;
    }

    @Override
    public void closeConnection() {
        try {
            serverSocketChannel.close();
        } catch (IOException ex) {
            LOGGER.warn("Could not close TransportHandler");
        }
    }

    @Override
    public void initialize() throws IOException {
        serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.socket().bind(new InetSocketAddress(port));
        serverSocketChannel.configureBlocking(false);
        accept = serverSocketChannel.accept();
        if (accept != null) {
            setStreams(accept.socket().getInputStream(), accept.socket().getOutputStream());
        }
    }

    public void recheck() {
        try {
            accept = serverSocketChannel.accept();
            if (accept != null) {
                setStreams(accept.socket().getInputStream(), accept.socket().getOutputStream());
            }
        } catch (IOException ex) {
            LOGGER.error("Could not accept connection", ex);
        }
    }
}
