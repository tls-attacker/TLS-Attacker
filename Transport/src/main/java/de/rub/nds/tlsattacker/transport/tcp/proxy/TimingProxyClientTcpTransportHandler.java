/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp.proxy;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ProxyableTransportHandler;
import de.rub.nds.tlsattacker.transport.TimeableTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TimingProxyClientTcpTransportHandler extends ClientTcpTransportHandler
        implements ProxyableTransportHandler, TimeableTransportHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Socket controlSocket;
    protected String proxyDataHostName = "127.0.0.1";
    protected int proxyDataPort = 4444;
    protected String proxyControlHostName = "127.0.0.1";
    protected int proxyControlPort = 5555;
    protected Long measurement = null;

    public TimingProxyClientTcpTransportHandler(Connection connection) {
        super(connection);
        this.proxyDataHostName = connection.getProxyDataHostname();
        this.proxyDataPort = connection.getProxyDataPort();
        this.proxyControlHostName = connection.getProxyControlHostname();
        this.proxyControlPort = connection.getProxyControlPort();
    }

    public TimingProxyClientTcpTransportHandler(
            long firstTimeout, long timeout, String hostname, int port) {
        super(firstTimeout, timeout, hostname, port);
    }

    @Override
    public byte[] fetchData() throws IOException {
        byte[] data = super.fetchData();
        byte[] controlData = new byte[8];
        if (data.length > 0) {
            int bytesRead = controlSocket.getInputStream().read(controlData);
            if (bytesRead != 8) {
                throw new IOException("Should return 64 bit unsigned int");
            }
            measurement = ByteBuffer.wrap(controlData).getLong();
        }
        return data;
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
    public void initialize() throws IOException {
        controlSocket = new Socket();
        controlSocket.connect(
                new InetSocketAddress(proxyControlHostName, proxyControlPort),
                (int) connectionTimeout);
        cachedSocketState = null;
        /* tell the proxy where the real server is */
        controlSocket.getOutputStream().write((hostname + "\n").getBytes());
        controlSocket.getOutputStream().write((Integer.toString(dstPort) + "\n").getBytes());
        controlSocket.getOutputStream().flush();
        hostname = proxyDataHostName;
        dstPort = proxyDataPort;
        super.initialize();
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed()
                || socket.isInputShutdown()
                || controlSocket.isClosed()
                || controlSocket.isInputShutdown();
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }

    @Override
    public Long getLastMeasurement() {
        return measurement;
    }
}
