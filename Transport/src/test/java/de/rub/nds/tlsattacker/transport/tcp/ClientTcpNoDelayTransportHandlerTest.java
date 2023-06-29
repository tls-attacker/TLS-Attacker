/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import org.junit.jupiter.api.Test;

public class ClientTcpNoDelayTransportHandlerTest {

    @Test
    public void testInitialize() throws IOException {
        try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            serverSocketChannel.socket().bind(new InetSocketAddress(0));
            serverSocketChannel.configureBlocking(false);
            ClientTcpNoDelayTransportHandler handler =
                    new ClientTcpNoDelayTransportHandler(
                            0, 0, "localhost", serverSocketChannel.socket().getLocalPort());
            handler.initialize();
            SocketChannel acceptChannel = serverSocketChannel.accept();
            assertNotNull(acceptChannel);
            assertTrue(handler.isInitialized());
        }
    }
}
