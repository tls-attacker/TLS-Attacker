/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

public class ClientTcpTransportHandlerIT {
    private static final Logger LOGGER = LogManager.getLogger();

    @Test
    public void testReceiveLargeDataAtOnce() throws IOException {
        for (int _iteration = 0; _iteration < 20; _iteration++) {
            try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
                serverSocketChannel.socket().bind(new InetSocketAddress(0));
                serverSocketChannel.configureBlocking(false);
                var handler =
                        new ClientTcpTransportHandler(
                                100, 100, "localhost", serverSocketChannel.socket().getLocalPort());
                handler.initialize();
                SocketChannel acceptChannel = serverSocketChannel.accept();
                assertNotNull(acceptChannel);
                Socket s = acceptChannel.socket();

                byte[] data = new byte[1000 * 1000];
                for (int i = 0; i < data.length; i++) {
                    data[i] = (byte) (Math.random() * 256);
                }

                s.getOutputStream().write(data);

                var res = new SilentByteArrayOutputStream();
                while (res.size() < data.length) {
                    var dataRead = handler.fetchData();
                    LOGGER.debug("Read {} bytes", dataRead.length);
                    res.write(dataRead);
                }
                assertArrayEquals(data, res.toByteArray());
            }
        }
    }
}
