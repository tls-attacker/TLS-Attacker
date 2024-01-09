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
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.SocketException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class UdpTransportHandler extends PacketbasedTransportHandler {

    private Logger LOGGER = LogManager.getLogger();

    protected DatagramSocket socket;

    protected int port;

    public UdpTransportHandler(Connection con) {
        super(con);
    }

    public UdpTransportHandler(long firstTimeout, long timeout, ConnectionEndType type) {
        super(timeout, type);
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        DatagramPacket packet;
        if (socket.isConnected()) {
            packet = new DatagramPacket(data, data.length);
        } else {
            if (useIpv6) {
                if (ipv6 != null) {
                    packet =
                            new DatagramPacket(
                                    data, data.length, Inet6Address.getByName(ipv6), port);
                } else {
                    throw new IOException("No IPv6 address set");
                }
            } else {
                if (ipv4 != null) {
                    packet =
                            new DatagramPacket(
                                    data, data.length, Inet4Address.getByName(ipv4), port);
                } else {
                    throw new IOException("No IPv4 address set");
                }
            }
        }
        socket.send(packet);
    }

    @Override
    public byte[] fetchData() throws IOException {
        setTimeout(timeout);
        DatagramPacket packet = new DatagramPacket(dataBuffer, RECEIVE_BUFFER_SIZE);
        socket.receive(packet);
        return Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
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
        socket.close();
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed();
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
