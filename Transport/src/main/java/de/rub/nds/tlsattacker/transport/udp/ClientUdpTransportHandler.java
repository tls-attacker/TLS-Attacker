/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.udp;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpInputStream;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ClientUdpTransportHandler extends TransportHandler {

    private final String hostname;
    private final int port;

    private DatagramSocket socket;

    public ClientUdpTransportHandler(long timeout, String hostname, int port) {
        super(timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
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
        socket = new DatagramSocket();
        socket.connect(new InetSocketAddress(hostname, port));
        socket.setSoTimeout((int) getTimeout());
        setStreams(new UdpInputStream(socket), new UdpOutputStream(socket));
    }

    public int getLocalPort() throws IOException {
        if (socket.isConnected()) {
            return socket.getLocalPort();
        }
        throw new IOException("Cannot retrieve local Port. Socket not connected");
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed();
    }
}
