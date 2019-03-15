/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.udp.stream;

import java.io.InputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;

public class UdpInputStream extends InputStream {

    private final static int BUFFER_SIZE = 16384;

    private DatagramSocket socket = null;

    /*
     * Stores the address of the originator of the last datagram.
     */
    private SocketAddress remoteAddress = null;

    private final byte[] dataBuffer = new byte[BUFFER_SIZE];

    private int packetSize = 0;

    private int index = 0;

    public UdpInputStream(DatagramSocket socket) {
        this.socket = socket;
    }

    @Override
    public void close() {
        if (!socket.isClosed()) {
            socket.close();
        }
    }

    @Override
    public int read() throws IOException {
        if (index == packetSize) {
            return -1;
        }
        index++;
        return dataBuffer[index - 1] & 0xff;
    }

    @Override
    public int available() throws IOException {
        if (packetSize - index == 0) {
            receive();
        }
        return packetSize - index;
    }

    private void receive() throws IOException {
        DatagramPacket packet = new DatagramPacket(dataBuffer, BUFFER_SIZE);
        try {
            socket.receive(packet);
            SocketAddress address = packet.getSocketAddress();
            if (address != null)
                remoteAddress = address;
            index = 0;
            packetSize = packet.getLength();
        } catch (SocketTimeoutException E) {
            packet = null;
        }
    }

    public SocketAddress getRemoteAddress() {
        return remoteAddress;
    }
}
