/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.socket;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TlsAttackerSocketTest {

    private TlsAttackerSocket socket;
    private State state;
    private Context context;

    private FakeTransportHandler transportHandler;

    public TlsAttackerSocketTest() {}

    @BeforeEach
    public void setUp() {
        Config config = Config.createConfig();
        state = new State(config, new WorkflowTrace());
        context = state.getContext();
        context.getTlsContext().setSelectedProtocolVersion(ProtocolVersion.TLS12);
        transportHandler = new FakeTransportHandler(ConnectionEndType.CLIENT);
        context.getTcpContext().setTransportHandler(transportHandler);
        socket = new TlsAttackerSocket(state);
    }

    /**
     * Test of sendRawBytes method, of class TlsAttackerSocket.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testSendRawBytes() throws IOException {
        socket.sendRawBytes(new byte[] {1, 2, 3});
        assertArrayEquals(new byte[] {1, 2, 3}, transportHandler.getSendByte());
    }

    /**
     * Test of receiveRawBytes method, of class TlsAttackerSocket.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testReceiveRawBytes() throws IOException {
        transportHandler.setFetchableByte(new byte[] {1, 2, 3});
        byte[] received = socket.receiveRawBytes();
        assertArrayEquals(new byte[] {1, 2, 3}, received);
    }

    /** Test of send method, of class TlsAttackerSocket. */
    @Test
    public void testSendString() {
        socket.send("test");
        byte[] sentBytes = transportHandler.getSendByte();
        assertArrayEquals(
                sentBytes,
                ArrayConverter.concatenate(
                        new byte[] {0x17, 0x03, 0x03, 0x00, 0x04},
                        "test".getBytes(StandardCharsets.US_ASCII)));
    }

    /** Test of send method, of class TlsAttackerSocket. */
    @Test
    public void testSendByteArray() {
        socket.send(new byte[] {0, 1, 2, 3});
        byte[] sentBytes = transportHandler.getSendByte();
        assertArrayEquals(sentBytes, new byte[] {0x17, 0x03, 0x03, 0x00, 0x04, 0, 1, 2, 3});
    }

    /**
     * Test of receiveBytes method, of class TlsAttackerSocket.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testReceiveBytes() throws IOException {
        transportHandler.setFetchableByte(new byte[] {0x17, 0x03, 0x03, 0x00, 0x03, 8, 8, 8});
        byte[] receivedBytes = socket.receiveBytes();
        assertArrayEquals(new byte[] {8, 8, 8}, receivedBytes);
    }

    /**
     * Test of receiveString method, of class TlsAttackerSocket.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testReceiveString() throws IOException {
        transportHandler.setFetchableByte(
                ArrayConverter.concatenate(
                        new byte[] {0x17, 0x03, 0x03, 0x00, 0x04},
                        "test".getBytes(StandardCharsets.US_ASCII)));
        String receivedString = socket.receiveString();
        assertEquals("test", receivedString);
    }
}
