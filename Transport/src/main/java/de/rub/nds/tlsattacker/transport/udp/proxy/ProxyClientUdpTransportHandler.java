/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.udp.proxy;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ProxyableTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ClientUdpTransportHandler;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;

/**
 * It establishes a control channel and data channel to the defined UDP proxy. The control channel
 * can be used to transmit where the real server is and the data channel can be used to transmit the
 * data to be sent. The UDP proxy should send the data to the real server and return the response
 * over the data channel.
 */
public class ProxyClientUdpTransportHandler extends ClientUdpTransportHandler
        implements ProxyableTransportHandler {

    protected DatagramSocket controlSocket;
    protected String proxyDataHostName = "127.0.0.1";
    protected int proxyDataPort = 4444;
    protected String proxyControlHostName = "127.0.0.1";
    protected int proxyControlPort = 5555;

    public ProxyClientUdpTransportHandler(Connection connection) {
        super(connection);
        this.proxyDataHostName = connection.getProxyDataHostname();
        this.proxyDataPort = connection.getProxyDataPort();
        this.proxyControlHostName = connection.getProxyControlHostname();
        this.proxyControlPort = connection.getProxyControlPort();
    }

    @Override
    public void setProxy(
            String dataChannelHost,
            int dataChanelPort,
            String controlChannelHost,
            int controlChanelPort) {
        proxyDataHostName = dataChannelHost;
        proxyDataPort = dataChanelPort;
        proxyControlHostName = controlChannelHost;
        proxyControlPort = controlChanelPort;
    }

    @Override
    public void initialize() throws IOException {
        controlSocket = new DatagramSocket();
        controlSocket.setSoTimeout((int) timeout);

        socket = new DatagramSocket();
        socket.setSoTimeout((int) timeout);

        /* tell the proxy where the real server is */
        byte[] message =
                (hostname + ":" + Integer.toString(port)).getBytes(StandardCharsets.ISO_8859_1);
        DatagramPacket packet = new DatagramPacket(message, message.length);
        controlSocket.send(packet);
    }

    @Override
    public void closeConnection() throws IOException {
        if (socket == null) {
            throw new IOException("Transporthandler is not initalized!");
        }
        socket.close();
        if (controlSocket == null) {
            throw new IOException("Transport handler is not initialized!");
        }
        controlSocket.close();
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed() || controlSocket.isClosed();
    }
}
