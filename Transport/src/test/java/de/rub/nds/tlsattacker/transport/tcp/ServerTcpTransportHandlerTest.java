/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.util.FreePortFinder;
import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.ExecutionException;
import org.junit.After;
import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class ServerTcpTransportHandlerTest {

    private ServerTcpTransportHandler handler;

    @Before
    public void setUp() {
        handler = new ServerTcpTransportHandler(100, 100, FreePortFinder.getPossiblyFreePort());
    }

    @After
    public void close() throws IOException {
        if (handler.isInitialized()) {
            handler.closeConnection();
        }
    }

    /**
     * Test of closeConnection method, of class ServerTcpTransportHandler.
     *
     * @throws java.io.IOException
     */
    @Test(expected = IOException.class)
    public void testCloseConnection() throws IOException {
        handler.closeConnection();
    }

    @Test
    public void testCloseClientConnection() throws IOException, InterruptedException, ExecutionException {
        handler.closeClientConnection(); // should do nothing

        // gives the server time to start
        handler.preInitialize();
        Socket socket = new Socket("localhost", handler.getSrcPort());

        handler.initialize();
        assertTrue(handler.isInitialized());
        assertNotNull(socket);
        assertTrue(socket.isConnected());
        try {
            socket.getOutputStream().write(123);
            socket.getOutputStream().flush();
        } catch (IOException E) {
            fail();
        }

        handler.closeServerSocket();
        try {
            socket.getOutputStream().write(123);
            socket.getOutputStream().flush();
        } catch (IOException E) {
            fail();
        }
        handler.closeClientConnection();
        Thread.sleep(50);
        try {
            socket.getOutputStream().write(123);
            socket.getOutputStream().flush();
            fail();
        } catch (IOException E) {
            // Should happen
        }
    }

    /**
     * Test of initialize method, of class ServerTcpTransportHandler.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testInitialize() throws Exception {
        assertFalse(handler.isInitialized());
        handler.preInitialize();
        Socket socket = new Socket("localhost", handler.getSrcPort());
        assertFalse(handler.isInitialized());

        handler.initialize();
        assertTrue(handler.isInitialized());
    }

    @Test
    public void fullTest() throws IOException, InterruptedException, ExecutionException {
        handler.preInitialize();
        Socket socket = new Socket("localhost", handler.getSrcPort());

        handler.initialize();

        assertTrue(handler.isInitialized());

        socket.getOutputStream().write(new byte[] { 0, 1, 2, 3 });
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, handler.fetchData());
        handler.sendData(new byte[] { 4, 3, 2, 1 });
        byte[] received = new byte[4];
        socket.getInputStream().read(received);
        assertArrayEquals(new byte[] { 4, 3, 2, 1 }, received);
    }

}
