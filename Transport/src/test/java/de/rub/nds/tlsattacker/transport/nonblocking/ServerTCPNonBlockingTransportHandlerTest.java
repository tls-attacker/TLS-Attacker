/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.nonblocking;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ServerTCPNonBlockingTransportHandlerTest {

    private ServerTCPNonBlockingTransportHandler handler;

    public ServerTCPNonBlockingTransportHandlerTest() {
    }

    @Before
    public void setUp() {
        handler = new ServerTCPNonBlockingTransportHandler(1000, 0);
    }

    @After
    public void clean() {
        try {
            handler.closeClientConnection();
        } catch (IOException ex) {
        }
        try {
            handler.closeConnection();
        } catch (IOException ex) {
        }
    }

    /**
     * Test of closeConnection method, of class
     * ServerTCPNonBlockingTransportHandler.
     *
     * @throws java.io.IOException
     */
    public void testCloseConnectionNotInitialised() throws IOException {
        handler.closeConnection();
    }

    @Test
    public void testCloseConnection() throws IOException {
        handler.initialize();
        new Socket().connect(new InetSocketAddress("localhost", handler.getPort()));
        handler.recheck(1000);
        handler.closeConnection();
        Exception ex = null;
        try {
            new Socket().connect(new InetSocketAddress("localhost", handler.getPort()));
        } catch (IOException E) {
            ex = E;
        }
        assertNotNull(ex);
    }

    @Test
    public void testCloseClientConnection() throws IOException {
        handler.initialize();
        Socket socket = new Socket();
        socket.setTcpNoDelay(true);
        socket.connect(new InetSocketAddress("localhost", handler.getPort()));

        handler.recheck(1000);
        Exception ex = null;
        assertNotNull(socket);
        assertTrue(socket.isConnected());
        handler.closeClientConnection();
        try {
            assertTrue(socket.getInputStream().read() == -1);
        } catch (IOException E) {
            ex = E;
            fail();
        }
        assertFalse(handler.isClosed());
        handler.closeConnection();

    }

    /**
     * Test of initialize method, of class ServerTCPNonBlockingTransportHandler.
     *
     * @throws java.lang.InterruptedException
     */
    @Test
    public void testInitialize() throws InterruptedException {
        try {
            handler.initialize();
            assertFalse(handler.isInitialized());
            handler.recheck();
            assertFalse(handler.isInitialized());
            new Socket().connect(new InetSocketAddress("localhost", handler.getPort()));
            handler.recheck(1000);

            assertTrue(handler.isInitialized());
        } catch (IOException ex) {
            fail("Encountered Exception");
        } finally {
            try {
                handler.closeConnection();
            } catch (IOException ex) {
            }
        }
    }

    /**
     * Test of recheck method, of class ServerTCPNonBlockingTransportHandler.
     *
     * @throws java.io.IOException
     */
    @Test(expected = IOException.class)
    public void testRecheck() throws IOException {
        handler.recheck();
    }

    @Test
    public void fullTest() throws IOException {
        Socket s = null;
        try {

            handler.initialize();
            s = new Socket();
            s.connect(new InetSocketAddress("localhost", handler.getPort()));
            handler.recheck(1000);
            assertTrue(handler.isInitialized());
            handler.sendData(new byte[] { 1, 2, 3 });
            byte[] receive = new byte[3];
            s.getInputStream().read(receive);
            assertArrayEquals(new byte[] { 1, 2, 3 }, receive);
            s.getOutputStream().write(new byte[] { 3, 2, 1 });
            s.getOutputStream().flush();
            byte[] fetchData = handler.fetchData();
            assertArrayEquals(new byte[] { 3, 2, 1 }, fetchData);
        } finally {
            handler.closeConnection();
            if (s != null) {
                s.close();
            }
        }
    }

}
