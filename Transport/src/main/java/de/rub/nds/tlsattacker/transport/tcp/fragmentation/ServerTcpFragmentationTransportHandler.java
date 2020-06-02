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

import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

public class ServerTcpFragmentationTransportHandler extends ServerTcpTransportHandler {

    public ServerTcpFragmentationTransportHandler(long firstTimeout, long timeout, int port) {
        super(firstTimeout, timeout, port);
    }

    public ServerTcpFragmentationTransportHandler(long firstTimeout, long timeout, ServerSocket serverSocket) throws IOException {
        super(firstTimeout, timeout, serverSocket);
    }

    public ServerTcpFragmentationTransportHandler(long firstTimeout, long timeout, Socket socket) throws IOException {
        super(firstTimeout, timeout, socket);
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        if (!isInitialized()) {
            throw new IOException("Transporthandler is not initalized!");
        }
        int pointer = 0;
        int chunk_size = (int)Math.ceil((double)data.length / 3);

        while (pointer < data.length - 1) {
            if (pointer + chunk_size > data.length - 1) {
                chunk_size = data.length - pointer;
            }

            byte[] slice = Arrays.copyOfRange(data, pointer, pointer + chunk_size);
            pointer += chunk_size;
            outStream.write(slice);
            outStream.flush();
        }
    }
}
