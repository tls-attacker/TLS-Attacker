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
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ServerTCPNonBlockingTransportHandlerTest {

    private ServerTCPNonBlockingTransportHandler handler;

    public ServerTCPNonBlockingTransportHandlerTest() {
    }

    @Before
    public void setUp() {
        handler = new ServerTCPNonBlockingTransportHandler(1000, 50000);
    }

    /**
     * Test of closeConnection method, of class
     * ServerTCPNonBlockingTransportHandler.
     */
    @Test(expected = IOException.class)
    public void testCloseConnectionNotInitialised() throws IOException {
        handler.closeConnection();
    }

    @Test
    public void testCloseConnection() throws IOException {
        handler.initialize();
        new Socket().connect(new InetSocketAddress("localhost", 50000));
        handler.recheck(1000);
        handler.closeConnection();
        Exception ex = null;
        try {
            new Socket().connect(new InetSocketAddress("localhost", 50000));
        } catch (IOException E) {
            ex = E;
        }
        assertNotNull(ex);
    }

    /**
     * Test of initialize method, of class ServerTCPNonBlockingTransportHandler.
     */
    @Test
    public void testInitialize() throws InterruptedException {
        try {
            handler.initialize();
            assertFalse(handler.isInitialized());
            handler.recheck();
            assertFalse(handler.isInitialized());
            new Socket().connect(new InetSocketAddress("localhost", 50000));
            handler.recheck(1000);

            assertTrue(handler.isInitialized());
        } catch (IOException ex) {
            ex.printStackTrace();
            fail("Encountered Exception");
        } finally {
            try {
                handler.closeConnection();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    /**
     * Test of recheck method, of class ServerTCPNonBlockingTransportHandler.
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
            s.connect(new InetSocketAddress("localhost", 50000));
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
