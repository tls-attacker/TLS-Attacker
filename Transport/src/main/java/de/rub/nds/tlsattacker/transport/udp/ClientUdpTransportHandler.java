/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.udp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientUdpTransportHandler extends UdpTransportHandler {

    private static final int RECEIVE_BUFFER_SIZE = 16384;

    private static final Logger LOGGER = LogManager.getLogger();

    protected String ipv4;

    protected String ipv6;

    protected String hostname;

    protected Integer sourcePort;

    private final byte[] dataBuffer = new byte[RECEIVE_BUFFER_SIZE];

    public ClientUdpTransportHandler(Connection con) {
        super(con);
        this.ipv4 = con.getIp();
        this.ipv6 = con.getIpv6();
        this.hostname = con.getHostname();
        this.port = con.getPort();
        this.sourcePort = con.getSourcePort();
    }

    public ClientUdpTransportHandler(long firstTimeout, long timeout, String ipv4, int port) {
        super(firstTimeout, timeout, ConnectionEndType.CLIENT);
        this.ipv4 = ipv4;
        this.port = port;
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
        if (firstReceived) {
            setTimeout(firstTimeout);
        } else {
            setTimeout(timeout);
        }
        firstReceived = false;
        DatagramPacket packet = new DatagramPacket(dataBuffer, RECEIVE_BUFFER_SIZE);
        socket.receive(packet);
        return Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
    }

    @Override
    public void preInitialize() throws IOException {
        // Nothing to do here
    }

    @Override
    public void initialize() throws IOException {
        LOGGER.debug("Initializing ClientUdpTransportHandler host: {}, port: {}", hostname, port);
        if (sourcePort == null || resetClientSourcePort) {
            socket = new DatagramSocket();
        } else {
            socket = new DatagramSocket(sourcePort);
        }
        socket.setSoTimeout((int) timeout);
        cachedSocketState = null;
        this.initialized = true;
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }
}
