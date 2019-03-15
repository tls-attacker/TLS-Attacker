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

    /*
     * The first time we wait for a message, we wait longer, in order to give
     * enough time for a tested client to respond.
     */
    public static final int DEFAULT_FIRST_TIMEOUT = 10000;

    private final int port;

    private DatagramSocket socket;

    private UdpInputStream udpInputStream;

    private boolean isFirstTimeout;

    private final long firstTimeout;

    public ServerUdpTransportHandler(long timeout, int port, long firstTimeout) {
        super(timeout, ConnectionEndType.SERVER);
        this.port = port;
        this.firstTimeout = firstTimeout;
    }

    public ServerUdpTransportHandler(long timeout, int port) {
        this(timeout, port, DEFAULT_FIRST_TIMEOUT);
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
        udpInputStream = new UdpInputStream(socket);
        isFirstTimeout = true;
        setStreams(new PushbackInputStream(udpInputStream), new UdpOutputStream(socket));

    }

    public void sendData(byte[] data) throws IOException {
        if (socket.isConnected()) {
            super.sendData(data);
        } else {
            LOGGER.error("Socket is not connected. Not sending.");
        }
    }

    public byte[] fetchData() throws IOException {
        byte[] bytes = new byte[] {};
        if (isFirstTimeout) {
            long time = System.currentTimeMillis();
            do {
                bytes = super.fetchData();
            } while (bytes.length == 0 && (System.currentTimeMillis() - time) < firstTimeout);
            isFirstTimeout = false;
        } else {
            bytes = super.fetchData();
        }

        if (!socket.isConnected() && udpInputStream.getRemoteAddress() != null) {
            socket.connect(udpInputStream.getRemoteAddress());
        }
        return bytes;
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed();
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }

}
