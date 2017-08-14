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
import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ServerTcpTransportHandlerTest {

    private ServerTcpTransportHandler handler;

    @Before
    public void setUp() {
        handler = new ServerTcpTransportHandler(100, 50005);
    }

    @After
    public void close() throws IOException {
        if (handler.isInitialized()) {
            handler.closeConnection();
        }
    }

    /**
     * Test of closeConnection method, of class ServerTcpTransportHandler.
     */
    @Test(expected = IOException.class)
    public void testCloseConnection() throws IOException {
        handler.closeConnection();
    }

    /**
     * Test of initialize method, of class ServerTcpTransportHandler.
     */
    @Test
    public void testInitialize() throws Exception {
        SocketOpenerCallable callable = new SocketOpenerCallable("localhost", 50005);
        Thread t = new Thread(new FutureTask(callable));
        t.start();
        handler.initialize();
        assertTrue(handler.isInitialized());
    }

    @Test
    public void fullTest() throws IOException, InterruptedException, ExecutionException {
        SocketOpenerCallable callable = new SocketOpenerCallable("localhost", 50005);
        FutureTask<Socket> task = new FutureTask(callable);
        Thread t = new Thread(task);
        t.start();
        handler.initialize();
        assertTrue(task.isDone());
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
