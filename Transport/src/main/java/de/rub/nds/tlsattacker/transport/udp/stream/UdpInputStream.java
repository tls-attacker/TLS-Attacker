/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.udp.stream;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketTimeoutException;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class UdpInputStream extends InputStream {

    private final static int BUFFER_SIZE = 16384;

    private DatagramSocket socket = null;

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
            receive();
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
            index = 0;
            packetSize = packet.getLength();
        } catch (SocketTimeoutException E) {
            packet = null;
        }
    }
}
