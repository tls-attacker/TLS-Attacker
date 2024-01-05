/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.tcp;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.util.FreePortFinder;
import java.io.IOException;
import java.net.Socket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ServerTcpTransportHandlerTest {

    private ServerTcpTransportHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new ServerTcpTransportHandler(100, 100, FreePortFinder.getPossiblyFreePort());
    }

    @AfterEach
    public void close() throws IOException {
        if (handler.isInitialized()) {
            handler.closeConnection();
        }
    }

    /** Test of closeConnection method, of class ServerTcpTransportHandler. */
    @Test
    public void testCloseConnection() {
        assertThrows(IOException.class, handler::closeConnection);
    }

    @Test
    public void testCloseClientConnection() throws IOException, InterruptedException {
        assertDoesNotThrow(handler::closeClientConnection);

        handler.preInitialize();
        try (Socket socket = new Socket("localhost", handler.getSrcPort())) {
            handler.initialize();
            assertTrue(handler.isInitialized());
            assertNotNull(socket);
            assertTrue(socket.isConnected());
            socket.getOutputStream().write(123);
            socket.getOutputStream().flush();
            handler.closeServerSocket();
            socket.getOutputStream().write(123);
            socket.getOutputStream().flush();
            handler.closeClientConnection();
            Thread.sleep(50);
            assertThrows(
                    IOException.class,
                    () -> {
                        socket.getOutputStream().write(123);
                        socket.getOutputStream().flush();
                    });
        }
    }

    /** Test of initialize method, of class ServerTcpTransportHandler. */
    @Test
    public void testInitialize() throws IOException {
        assertFalse(handler.isInitialized());
        handler.preInitialize();
        try (Socket ignored = new Socket("localhost", handler.getSrcPort())) {
            assertFalse(handler.isInitialized());
            handler.initialize();
            assertTrue(handler.isInitialized());
        }
    }

    @Test
    public void fullTest() throws IOException {
        handler.preInitialize();
        try (Socket socket = new Socket("localhost", handler.getSrcPort())) {
            handler.initialize();
            assertTrue(handler.isInitialized());
            socket.getOutputStream().write(new byte[] {0, 1, 2, 3});
            assertArrayEquals(new byte[] {0, 1, 2, 3}, handler.fetchData());
            handler.sendData(new byte[] {4, 3, 2, 1});
            byte[] received = new byte[4];
            assertEquals(4, socket.getInputStream().read(received));
            assertArrayEquals(new byte[] {4, 3, 2, 1}, received);
        }
    }
}
