/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp.proxy;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class TimingProxyClientTcpTransportHandlerTest {

    private TimingProxyClientTcpTransportHandler handler;

    /** Test of closeConnection method, of class TimingProxyClientTcpTransportHandler. */
    @Test
    public void testCloseConnection() throws IOException {
        handler = new TimingProxyClientTcpTransportHandler(100, 100, "localhost", 0);
        assertThrows(IOException.class, handler::closeConnection);
    }

    /** Test of initialize method, of class TimingProxyClientTcpTransportHandler. */
    @Test
    @Disabled(
            "Timing proxy needs to be started manually, test will fail otherwise. Therefore disabled until fixed.")
    public void testInitialize() throws IOException {
        try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            serverSocketChannel.socket().bind(new InetSocketAddress(0));
            serverSocketChannel.configureBlocking(false);
            handler =
                    new TimingProxyClientTcpTransportHandler(
                            100, 100, "127.0.0.1", serverSocketChannel.socket().getLocalPort());
            handler.setProxy("127.0.0.1", 4444, "127.0.0.1", 5555);
            handler.initialize();
            SocketChannel acceptChannel = serverSocketChannel.accept();
            assertNotNull(acceptChannel);
            assertTrue(handler.isInitialized());
        }
    }

    @Test
    @Disabled(
            "Timing proxy needs to be started manually, test will fail otherwise. Therefore disabled until fixed.")
    public void fullTest() throws IOException {
        Socket s;
        try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            serverSocketChannel.socket().bind(new InetSocketAddress(0));
            serverSocketChannel.configureBlocking(false);
            handler =
                    new TimingProxyClientTcpTransportHandler(
                            100, 100, "127.0.0.1", serverSocketChannel.socket().getLocalPort());
            handler.setProxy("127.0.0.1", 4444, "127.0.0.1", 5555);
            handler.initialize();
            SocketChannel acceptChannel = serverSocketChannel.accept();
            assertNotNull(acceptChannel);
            s = acceptChannel.socket();
            handler.sendData(new byte[] {1, 2, 3});
            byte[] receive = new byte[3];
            assertEquals(3, s.getInputStream().read(receive));
            assertArrayEquals(new byte[] {1, 2, 3}, receive);
            s.getOutputStream().write(new byte[] {6, 6, 6});
            byte[] fetchData = handler.fetchData();
            assertArrayEquals(new byte[] {6, 6, 6}, fetchData);
            long timing = handler.getLastMeasurement();
            assertTrue(timing > 0);
        }
    }
}
