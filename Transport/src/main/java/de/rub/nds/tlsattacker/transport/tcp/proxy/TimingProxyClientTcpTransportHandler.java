/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp.proxy;

import de.rub.nds.tlsattacker.transport.ProxyableTransportHandler;
import de.rub.nds.tlsattacker.transport.TimeableTransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;

public class TimingProxyClientTcpTransportHandler extends TransportHandler implements ProxyableTransportHandler,
        TimeableTransportHandler {

    protected Socket dataSocket;
    protected Socket controlSocket;
    protected String hostname;
    protected int port;
    protected String proxyDataHostName = "127.0.0.1";
    protected int proxyDataPort = 4444;
    protected String proxyControlHostName = "127.0.0.1";
    protected int proxyControlPort = 5555;
    protected long measurement = 0;

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

    public TimingProxyClientTcpTransportHandler(Connection connection) {
        super(connection.getTimeout(), ConnectionEndType.CLIENT);
        this.hostname = connection.getHostname();
        this.port = connection.getPort();
        this.proxyDataHostName = connection.getProxyDataHostname();
        this.proxyDataPort = connection.getProxyDataPort();
        this.proxyControlHostName = connection.getProxyControlHostname();
        this.proxyControlPort = connection.getProxyControlPort();
    }

    public TimingProxyClientTcpTransportHandler(long timeout, String hostname, int port) {
        super(timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.port = port;
    }

    @Override
    public void setProxy(String dataChanelHost, int dataChanelPort, String controlChanelHost, int controlChanelPort) {
        proxyDataHostName = dataChanelHost;
        proxyDataPort = dataChanelPort;
        proxyControlHostName = controlChanelHost;
        proxyControlPort = controlChanelPort;
    }

    @Override
    public void closeConnection() throws IOException {
        if (dataSocket == null) {
            throw new IOException("Transporthandler is not initalized!");
        }
        dataSocket.close();

        if (controlSocket == null) {
            throw new IOException("Transporthandler is not initalized!");
        }
        controlSocket.close();
    }

    @Override
    public void initialize() throws IOException {
        controlSocket = new Socket();
        controlSocket.connect(new InetSocketAddress(proxyControlHostName, proxyControlPort), (int) timeout);

        dataSocket = new Socket();
        dataSocket.connect(new InetSocketAddress(proxyDataHostName, proxyDataPort), (int) timeout);
        if (!dataSocket.isConnected()) {
            throw new IOException("Could not connect to " + proxyDataHostName + ":" + proxyDataPort);
        }

        /* tell the proxy where the real server is */
        controlSocket.getOutputStream().write((hostname + "\n").getBytes());
        controlSocket.getOutputStream().write((Integer.toString(port) + "\n").getBytes());
        controlSocket.getOutputStream().flush();

        setStreams(new PushbackInputStream(dataSocket.getInputStream()), dataSocket.getOutputStream());
    }

    @Override
    public boolean isClosed() throws IOException {
        return dataSocket.isClosed() || dataSocket.isInputShutdown() || controlSocket.isClosed()
                || controlSocket.isInputShutdown();
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }

    /**
     * Checks the current SocketState. NOTE: If you check the SocketState and
     * Data is received during the Check the current State of the
     * TransportHandler will get messed up and an Exception will be thrown.
     *
     * @return The current SocketState
     * @throws de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException
     */
    public SocketState getSocketState() throws InvalidTransportHandlerStateException {
        try {
            if (dataSocket.getInputStream().available() > 0) {
                return SocketState.DATA_AVAILABLE;
            }
            dataSocket.setSoTimeout(1);
            int read = dataSocket.getInputStream().read();
            if (read == -1) {
                return SocketState.CLOSED;
            } else {
                throw new InvalidTransportHandlerStateException("Received Data during SocketState check");
            }
        } catch (SocketTimeoutException ex) {
            return SocketState.TIMEOUT;
        } catch (SocketException ex) {
            return SocketState.SOCKET_EXCEPTION;
        } catch (IOException ex) {
            return SocketState.IO_EXCEPTION;
        }
    }

    @Override
    public long getLastMeasurement() {
        return measurement;
    }
}
