/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.stream;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class StreamTransportHandlerTest {

    private StreamTransportHandler handler;

    private ByteArrayOutputStream outputStream;

    private ByteArrayInputStream inputStream;

    @BeforeEach
    public void setUp() {
        outputStream = new ByteArrayOutputStream();
        inputStream = new ByteArrayInputStream(new byte[] {4, 3, 2, 1});
        handler =
                new StreamTransportHandler(
                        100, 100, ConnectionEndType.CLIENT, inputStream, outputStream);
    }

    /** Test of closeConnection method, of class StreamTransportHandler. */
    @Test()
    public void testCloseConnection() {
        assertThrows(IOException.class, handler::closeConnection);
    }

    /** Test of initialize method, of class StreamTransportHandler. */
    @Test
    public void testInitialize() throws IOException {
        assertFalse(handler.isInitialized());
        handler.initialize();
        assertTrue(handler.isInitialized());
    }

    /** Test of getInputStream method, of class StreamTransportHandler. */
    @Test
    public void testGetInputStream() {
        assertNotNull(handler.getInputStream());
    }

    /** Test of getOutputStream method, of class StreamTransportHandler. */
    @Test
    public void testGetOutputStream() {
        assertNotNull(handler.getOutputStream());
    }

    @Test
    public void fullTest() throws IOException {
        handler.initialize();
        handler.sendData(new byte[] {0, 1, 2, 3});
        assertArrayEquals(new byte[] {0, 1, 2, 3}, outputStream.toByteArray());
        byte[] fetchData = handler.fetchData();
        assertArrayEquals(new byte[] {4, 3, 2, 1}, fetchData);
    }

    @Test
    public void testCloseClientConnection() throws IOException {
        handler.initialize();
        assertThrows(UnsupportedOperationException.class, handler::closeClientConnection);
    }
}
