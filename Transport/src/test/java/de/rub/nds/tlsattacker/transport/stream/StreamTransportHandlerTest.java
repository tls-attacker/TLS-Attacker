/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.stream;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class StreamTransportHandlerTest {

    private StreamTransportHandler handler;

    private ByteArrayOutputStream outputStream;

    private ByteArrayInputStream inputStream;

    @Before
    public void setUp() {
        outputStream = new ByteArrayOutputStream();
        inputStream = new ByteArrayInputStream(new byte[] { 4, 3, 2, 1 });
        handler = new StreamTransportHandler(100, ConnectionEndType.CLIENT, inputStream, outputStream);
    }

    /**
     * Test of closeConnection method, of class StreamTransportHandler.
     *
     * @throws java.io.IOException
     */
    @Test(expected = IOException.class)
    public void testCloseConnection() throws IOException {
        handler.closeConnection();
    }

    /**
     * Test of initialize method, of class StreamTransportHandler.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testInitialize() throws Exception {
        assertFalse(handler.isInitialized());
        handler.initialize();
        assertTrue(handler.isInitialized());
    }

    /**
     * Test of getInputStream method, of class StreamTransportHandler.
     */
    @Test
    public void testGetInputStream() {
        assertNotNull(handler.getInputStream());
    }

    /**
     * Test of getOutputStream method, of class StreamTransportHandler.
     */
    @Test
    public void testGetOutputStream() {
        assertNotNull(handler.getOutputStream());
    }

    @Test
    public void fullTest() throws IOException {
        handler.initialize();
        handler.sendData(new byte[] { 0, 1, 2, 3 });
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, outputStream.toByteArray());
        byte[] fetchData = handler.fetchData();
        assertArrayEquals(new byte[] { 4, 3, 2, 1 }, fetchData);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testCloseClientconnection() throws IOException {
        handler.initialize();
        handler.closeClientConnection();
    }
}
