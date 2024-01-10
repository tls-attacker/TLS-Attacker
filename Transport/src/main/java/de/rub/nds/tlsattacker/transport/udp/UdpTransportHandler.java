/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.udp;

import de.rub.nds.tlsattacker.PacketbasedTransportHandler;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class UdpTransportHandler extends PacketbasedTransportHandler {

    private Logger LOGGER = LogManager.getLogger();

    protected DatagramSocket socket;

    protected int port;

    private final int RECEIVE_BUFFER_SIZE = 65536;

    private final byte[] dataBuffer = new byte[RECEIVE_BUFFER_SIZE];

    /**
     * It can happen that we only read half a packet. If we do that, we need to cache the remainder
     * of the packet and return it the next time somebody reads
     */
    private ByteArrayInputStream dataBufferInputStream;

    public UdpTransportHandler(Connection con) {
        super(con);
    }

    public UdpTransportHandler(long timeout, ConnectionEndType type) {
        super(timeout, type);
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        DatagramPacket packet = new DatagramPacket(data, data.length);
        socket.send(packet);
    }

    @Override
    public byte[] fetchData() throws IOException {
        if (dataBufferInputStream != null && dataBufferInputStream.available() > 0) {
            return dataBufferInputStream.readAllBytes();
        } else {
            setTimeout(timeout);
            DatagramPacket packet = new DatagramPacket(dataBuffer, RECEIVE_BUFFER_SIZE);
            socket.receive(packet);
            return Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
        }
    }

    @Override
    public byte[] fetchData(int amountOfData) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(dataBufferInputStream.readAllBytes());
        setTimeout(timeout);
        // Read packets till we got atleast amountOfData bytes
        while (outputStream.size() < amountOfData) {
            DatagramPacket packet = new DatagramPacket(dataBuffer, RECEIVE_BUFFER_SIZE);
            socket.receive(packet);
            outputStream.write(Arrays.copyOfRange(packet.getData(), 0, packet.getLength()));
        }
        // Now we got atleast amount of data bytes. If we got more, cache them
        dataBufferInputStream = new ByteArrayInputStream(outputStream.toByteArray());
        return dataBufferInputStream.readNBytes(amountOfData);
    }

    @Override
    public void setTimeout(long timeout) {
        try {
            this.timeout = timeout;
            if (socket != null) {
                socket.setSoTimeout((int) timeout);
            }
        } catch (SocketException ex) {
            LOGGER.error("Could not adjust socket timeout", ex);
        }
    }

    @Override
    public void closeConnection() throws IOException {
        if (socket != null) {
            socket.close();
        }
    }

    @Override
    public boolean isClosed() throws IOException {
        if (socket != null) {
            return socket.isClosed();
        } else {
            return true;
        }
    }

    public int getSrcPort() {
        if (socket == null) {
            // mimic socket.getLocalPort() behavior as if socket was closed
            return -1;
        }
        return socket.getLocalPort();
    }

    public int getDstPort() {
        if (socket == null) {
            // mimic socket.getPort() behavior as if socket was not connected
            return -1;
        }
        return socket.getPort();
    }
}
