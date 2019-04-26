/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.udp;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.DatagramSocket;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpInputStream;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpOutputStream;

public class ServerUdpTransportHandler extends TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    private final int port;

    private DatagramSocket socket;

    public ServerUdpTransportHandler(long timeout, int port) {
        super(timeout, ConnectionEndType.SERVER, false);
        this.port = port;
    }

    @Override
    public void closeConnection() throws IOException {
        socket.close();
        inStream.close();
        outStream.close();
    }

    @Override
    public void initialize() throws IOException {
        socket = new DatagramSocket(port);
        socket.setSoTimeout((int) getTimeout());
        setStreams(new PushbackInputStream(new UdpInputStream(socket, true)), new UdpOutputStream(socket));
        // this could be made an option
        waitOnReceive();
    }

    /*
     * Provides a routine equivalent to TCP's accept method. Blocks until a
     * client "connects", meaning that data is available to be read.
     */
    private void waitOnReceive() throws IOException {
        while (inStream.available() == 0) {
            try {
                Thread.sleep(1);
            } catch (InterruptedException _) {
            }
        }
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed();
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }

    public int getPort() {
        return port;
    }
}
