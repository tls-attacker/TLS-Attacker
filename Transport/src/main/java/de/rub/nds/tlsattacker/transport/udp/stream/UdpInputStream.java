/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.udp.stream;

import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class UdpInputStream extends InputStream {

    private static final int BUFFER_SIZE = 16384;

    private DatagramSocket socket = null;

    /**
     * A buffer used to store the content of received datagrams.
     */
    private final byte[] dataBuffer = new byte[BUFFER_SIZE];

    /**
     * The size of the last received datagram
     */
    private int packetSize = 0;

    /**
     * The index of the next byte to be read in the datagram
     */
    private int index = 0;

    /**
     * If set to true, on datagram receipt it connects the socket to the datagram's source address. This is useful if
     * the source address is not pre-set, such as in {@link ServerUdpTransportHandler}'s case.
     */
    private boolean connectOnReceive;

    public UdpInputStream(DatagramSocket socket, boolean connectOnReceive) {
        this.socket = socket;
        this.connectOnReceive = connectOnReceive;
    }

    @Override
    public void close() {
        if (!socket.isClosed()) {
            socket.close();
        }
    }

    /**
     * Blocks until data is received from a UDP peer. Will never return -1, as UDP has no mechanism of notifying that
     * all data has been sent. To avoid blocking indefinitely, should be called only once data is available.
     */
    @SuppressWarnings("CheckStyle")
    @Override
    public int read() throws IOException {
        // we wait until data is available
        while (available() == 0) {
            try {
                Thread.sleep(1);
            } catch (InterruptedException ignored) {
            }
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

    /*
     * Receives a packet or times out. On receipt, updates packetSize and index.
     */
    private DatagramPacket receive() throws IOException {
        DatagramPacket packet = new DatagramPacket(dataBuffer, BUFFER_SIZE);
        socket.receive(packet);
        index = 0;
        packetSize = packet.getLength();

        if (connectOnReceive && !socket.isConnected()) {
            socket.connect(packet.getSocketAddress());
        }

        return packet;
    }
}
