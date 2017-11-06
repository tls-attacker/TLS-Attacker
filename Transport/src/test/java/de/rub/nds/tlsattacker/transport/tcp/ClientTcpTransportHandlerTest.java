/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;


public class ClientTcpTransportHandlerTest {

    private ClientTcpTransportHandler handler;

    @Before
    public void setUp() {
        handler = new ClientTcpTransportHandler(100, "localhost", 50001);
    }

    /**
     * Test of closeConnection method, of class ClientTcpTransportHandler.
     * 
     * @throws java.io.IOException
     */
    @Test(expected = IOException.class)
    public void testCloseConnection() throws IOException {
        handler.closeConnection();
    }

    /**
     * Test of initialize method, of class ClientTcpTransportHandler.
     * 
     * @throws java.io.IOException
     */
    @Test
    public void testInitialize() throws IOException {
        ServerSocketChannel serverSocketChannel = null;
        try {
            serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.socket().bind(new InetSocketAddress(50001));
            serverSocketChannel.configureBlocking(false);
            handler.initialize();
            SocketChannel acceptChannel = serverSocketChannel.accept();
            assertNotNull(acceptChannel);
            assertTrue(handler.isInitialized());
        } finally {
            if (serverSocketChannel != null) {
                try {
                    serverSocketChannel.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }
    }

    @Test
    public void fullTest() throws IOException {
        ServerSocketChannel serverSocketChannel = null;
        Socket s = null;
        try {
            serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.socket().bind(new InetSocketAddress(50001));
            serverSocketChannel.configureBlocking(false);
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
        } finally {
            if (serverSocketChannel != null) {
                try {
                    serverSocketChannel.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }

    }

}
