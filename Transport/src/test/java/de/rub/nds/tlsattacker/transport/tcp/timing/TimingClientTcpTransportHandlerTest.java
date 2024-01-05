/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp.timing;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import org.junit.jupiter.api.Test;

public class TimingClientTcpTransportHandlerTest {

    private TimingClientTcpTransportHandler handler;

    /** Test of closeConnection method, of class TimingClientTcpTransportHandler. */
    @Test
    public void testCloseConnection() {
        handler = new TimingClientTcpTransportHandler(100, 100, "localhost", 0);
        assertThrows(IOException.class, handler::closeConnection);
    }

    /** Test of initialize method, of class TimingClientTcpTransportHandler. */
    @Test
    public void testInitialize() throws IOException {
        try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            serverSocketChannel.socket().bind(new InetSocketAddress(0));
            serverSocketChannel.configureBlocking(false);
            handler =
                    new TimingClientTcpTransportHandler(
                            100, 100, "localhost", serverSocketChannel.socket().getLocalPort());
            handler.initialize();
            SocketChannel acceptChannel = serverSocketChannel.accept();
            assertNotNull(acceptChannel);
            assertTrue(handler.isInitialized());
        }
    }

    @Test
    public void fullTest() throws IOException {
        try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            serverSocketChannel.socket().bind(new InetSocketAddress(0));
            serverSocketChannel.configureBlocking(false);
            handler =
                    new TimingClientTcpTransportHandler(
                            100, 100, "localhost", serverSocketChannel.socket().getLocalPort());
            handler.initialize();
            SocketChannel acceptChannel = serverSocketChannel.accept();
            assertNotNull(acceptChannel);
            Socket s = acceptChannel.socket();
            s.getOutputStream().write(new byte[] {6, 6, 6});
            handler.sendData(new byte[] {1, 2, 3});
            byte[] receive = new byte[3];
            assertEquals(3, s.getInputStream().read(receive));
            assertArrayEquals(new byte[] {1, 2, 3}, receive);
            byte[] fetchData = handler.fetchData();
            assertArrayEquals(new byte[] {6, 6, 6}, fetchData);
            long timing = handler.getLastMeasurement();
            assertTrue(timing > 0);
        }
    }
}
