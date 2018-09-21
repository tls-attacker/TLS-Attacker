/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.nonblocking.SocketOpenerCallable;
import de.rub.nds.tlsattacker.util.FreePortFinder;
import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ServerTcpTransportHandlerTest {

    private ServerTcpTransportHandler handler;

    @Before
    public void setUp() {
        handler = new ServerTcpTransportHandler(100, FreePortFinder.getPossiblyFreePort());
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
        SocketOpenerCallable callable = new SocketOpenerCallable("localhost", handler.getPort());
        FutureTask task = new FutureTask(callable);
        Thread t = new Thread(task);
        t.start();
        handler.initialize();
        assertTrue(handler.isInitialized());
        Socket socket = (Socket) task.get();
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
        SocketOpenerCallable callable = new SocketOpenerCallable("localhost", handler.getPort());
        Thread t = new Thread(new FutureTask(callable));
        t.start();
        handler.initialize();
        assertTrue(handler.isInitialized());
    }

    @Test
    public void fullTest() throws IOException, InterruptedException, ExecutionException {
        SocketOpenerCallable callable = new SocketOpenerCallable("localhost", handler.getPort());
        FutureTask<Socket> task = new FutureTask(callable);
        Thread t = new Thread(task);
        t.start();
        handler.initialize();
        long time = System.currentTimeMillis();
        long timeout = 1000;
        while (!task.isDone()) {
            if (System.currentTimeMillis() > time + timeout) {
                fail("Starting task timed out.");
            }
        }
        assertTrue(handler.isInitialized());
        Socket socket = task.get();
        socket.getOutputStream().write(new byte[] { 0, 1, 2, 3 });
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, handler.fetchData());
        handler.sendData(new byte[] { 4, 3, 2, 1 });
        byte[] received = new byte[socket.getInputStream().available()];
        socket.getInputStream().read(received);
        assertArrayEquals(new byte[] { 4, 3, 2, 1 }, received);
    }

}
