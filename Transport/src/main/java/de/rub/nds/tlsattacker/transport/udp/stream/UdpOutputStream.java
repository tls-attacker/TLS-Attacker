/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.udp.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class UdpOutputStream extends OutputStream {

    private static final int BUFFER_SIZE = 16384;

    private final DatagramSocket socket;
    private String hostname;
    private int port;
    private final byte[] dataBuffer = new byte[BUFFER_SIZE];
    private int index;

    public UdpOutputStream(DatagramSocket socket) {
        this.socket = socket;
    }

    public UdpOutputStream(DatagramSocket socket, String hostname, int port) {
        this.socket = socket;
        this.hostname = hostname;
        this.port = port;
    }

    @Override
    public void write(int i) throws IOException {
        dataBuffer[index] = (byte) (i & 0x0ff);
        index++;

        if (index >= dataBuffer.length) {
            flush();
        }
    }

    @Override
    public void close() throws IOException {
        if (!socket.isClosed()) {
            socket.close();
        }
    }

    @Override
    public void flush() throws IOException {
        byte[] outData = new byte[index];
        System.arraycopy(dataBuffer, 0, outData, 0, index);
        DatagramPacket packet;
        if (socket.isConnected()) {
            packet = new DatagramPacket(outData, index);
        } else {
            packet = new DatagramPacket(outData, index, InetAddress.getByName(hostname), port);
        }
        socket.send(packet);
        index = 0;
    }
}
