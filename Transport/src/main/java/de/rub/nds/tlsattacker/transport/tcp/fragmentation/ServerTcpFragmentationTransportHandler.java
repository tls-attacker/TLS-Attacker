/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp.fragmentation;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

public class ServerTcpFragmentationTransportHandler extends ServerTcpTransportHandler {

    private int packetChunks = 3;

    public ServerTcpFragmentationTransportHandler(Connection con) {
        super(con);
    }

    public ServerTcpFragmentationTransportHandler(long firstTimeout, long timeout, int port) {
        super(firstTimeout, timeout, port);
    }

    public ServerTcpFragmentationTransportHandler(
            long firstTimeout, long timeout, ServerSocket serverSocket) throws IOException {
        super(firstTimeout, timeout, serverSocket);
    }

    public ServerTcpFragmentationTransportHandler(Connection con, Socket socket)
            throws IOException {
        super(con, socket);
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
        }
    }

    public int getPacketChunks() {
        return packetChunks;
    }

    public void setPacketChunks(int packetChunks) {
        this.packetChunks = packetChunks;
    }
}
