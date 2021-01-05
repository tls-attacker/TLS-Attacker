/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.transport.tcp.fragmentation;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Arrays;

public class ClientTcpFragmentationTransportHandler extends ClientTcpTransportHandler {

    private static final int DEFAULT_CONNECTION_TIMEOUT_MILLISECONDS = 60000;
    private int packetChunks = 3;

    public ClientTcpFragmentationTransportHandler(Connection connection) {
        this(DEFAULT_CONNECTION_TIMEOUT_MILLISECONDS, connection.getFirstTimeout(), connection.getTimeout(), connection
            .getIp(), connection.getPort());
    }

    public ClientTcpFragmentationTransportHandler(long firstTimeout, long timeout, String hostname, int port) {
        this(timeout, firstTimeout, timeout, hostname, port);
    }

    public ClientTcpFragmentationTransportHandler(long connectionTimeout, long firstTimeout, long timeout,
        String hostname, int port) {
        super(connectionTimeout, firstTimeout, timeout, hostname, port);
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        if (!isInitialized()) {
            throw new IOException("Transporthandler is not initalized!");
        }
        int pointer = 0;
        int chunk_size = (int) Math.ceil((double) data.length / packetChunks);

        while (pointer <= data.length - 1) {
            if (pointer + chunk_size > data.length - 1) {
                chunk_size = data.length - pointer;
            }

            byte[] slice = Arrays.copyOfRange(data, pointer, pointer + chunk_size);
            pointer += chunk_size;
            outStream.write(slice);
            outStream.flush();
            try {
                Thread.sleep(10);
            } catch (Exception e) {
            }

        }
    }

    public int getPacketChunks() {
        return packetChunks;
    }

    public void setPacketChunks(int packetChunks) {
        this.packetChunks = packetChunks;
    }
}
