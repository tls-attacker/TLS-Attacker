/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
        handler = new ServerTCPNonBlockingTransportHandler(1000, 1000, 0);
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
     * Test of closeConnection method, of class ServerTCPNonBlockingTransportHandler.
     *
     * @throws java.io.IOException
     */
    public void testCloseConnectionNotInitialised() throws IOException {
        handler.closeConnection();
    }

    @Test
    public void testCloseConnection() throws IOException, InterruptedException {
        handler.initialize();
        new Socket().connect(new InetSocketAddress("localhost", handler.getPort()));
        while (!handler.isInitialized()) {
            Thread.currentThread().sleep(10);
            // Without this a race condition can occur with the future...
        }
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
    public void testCloseClientConnection() throws IOException, InterruptedException {
        handler.initialize();
        Socket socket = new Socket();
        socket.setTcpNoDelay(false);
        socket.connect(new InetSocketAddress("localhost", handler.getPort()));
        while (!handler.isInitialized()) {
            Thread.currentThread().sleep(10);
            // Without this a race condition can occur with the future...
        }
        assertTrue(handler.isInitialized());
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
            handler.isInitialized();
            assertFalse(handler.isInitialized());
            new Socket().connect(new InetSocketAddress("localhost", handler.getPort()));
            while (!handler.isInitialized()) {
                Thread.currentThread().sleep(10);
                // Without this a race condition can occur with the future...
            }
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

    @Test
    public void fullTest() throws IOException, InterruptedException {
        Socket s = null;
        try {

            handler.initialize();
            s = new Socket();
            s.connect(new InetSocketAddress("localhost", handler.getPort()));
            handler.isInitialized();
            while (!handler.isInitialized()) {
                Thread.currentThread().sleep(10);
                // Without this a race condition can occur with the future...
            }
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
