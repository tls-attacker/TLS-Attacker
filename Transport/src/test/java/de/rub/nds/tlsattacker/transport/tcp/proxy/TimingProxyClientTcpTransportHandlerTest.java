/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp.proxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import static org.junit.Assert.*;

import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class TimingProxyClientTcpTransportHandlerTest {

    private TimingProxyClientTcpTransportHandler handler;

    @Before
    public void setUp() {
    }

    /**
     * Test of closeConnection method, of class
     * TimingProxyClientTcpTransportHandler.
     *
     * @throws java.io.IOException
     */
    @Test(expected = IOException.class)
    public void testCloseConnection() throws IOException {
        handler = new TimingProxyClientTcpTransportHandler(100, "localhost", 0);
        handler.closeConnection();
    }

    /**
     * Test of initialize method, of class TimingProxyClientTcpTransportHandler.
     *
     * @throws java.io.IOException
     */
    @Test
    @Category(IntegrationTests.class)
    public void testInitialize() throws IOException {
        ServerSocketChannel serverSocketChannel = null;
        try {
            serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.socket().bind(new InetSocketAddress(0));
            serverSocketChannel.configureBlocking(false);
            handler = new TimingProxyClientTcpTransportHandler(100, "127.0.0.1", serverSocketChannel.socket()
                    .getLocalPort());
            handler.setProxy("127.0.0.1", 4444, "127.0.0.1", 5555);
            handler.initialize();
            SocketChannel acceptChannel = serverSocketChannel.accept();
            assertNotNull(acceptChannel);
            assertTrue(handler.isInitialized());
        } finally {
            if (serverSocketChannel != null) {
                try {
                    serverSocketChannel.close();
                } catch (IOException ex) {
                }
            }
        }
    }

    @Test
    @Category(IntegrationTests.class)
    public void fullTest() throws IOException {
        ServerSocketChannel serverSocketChannel = null;
        Socket s = null;
        try {
            serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.socket().bind(new InetSocketAddress(0));
            serverSocketChannel.configureBlocking(false);
            handler = new TimingProxyClientTcpTransportHandler(100, "127.0.0.1", serverSocketChannel.socket()
                    .getLocalPort());
            handler.setProxy("127.0.0.1", 4444, "127.0.0.1", 5555);
            handler.initialize();
            SocketChannel acceptChannel = serverSocketChannel.accept();
            assertNotNull(acceptChannel);
            s = acceptChannel.socket();
            handler.sendData(new byte[] { 1, 2, 3 });
            byte[] receive = new byte[3];
            s.getInputStream().read(receive);
            assertArrayEquals(new byte[] { 1, 2, 3 }, receive);
            s.getOutputStream().write(new byte[] { 6, 6, 6 });
            byte[] fetchData = handler.fetchData();
            assertArrayEquals(new byte[] { 6, 6, 6 }, fetchData);
            long timing = handler.getLastMeasurement();
            assertTrue(timing > 0);
        } finally {
            if (serverSocketChannel != null) {
                try {
                    serverSocketChannel.close();
                } catch (IOException ex) {
                }
            }
        }

    }
}
