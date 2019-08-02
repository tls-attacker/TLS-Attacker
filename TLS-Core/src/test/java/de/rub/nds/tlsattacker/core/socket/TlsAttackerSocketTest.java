/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.socket;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.nio.charset.Charset;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class TlsAttackerSocketTest {

    private TlsAttackerSocket socket;
    private State state;
    private TlsContext context;

    private FakeTransportHandler transportHandler;

    public TlsAttackerSocketTest() {
    }

    @Before
    public void setUp() {
        Config config = Config.createConfig();
        state = new State(config, new WorkflowTrace());
        context = state.getTlsContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        transportHandler = new FakeTransportHandler(ConnectionEndType.CLIENT);
        context.setTransportHandler(transportHandler);
        socket = new TlsAttackerSocket(state);
        context.setRecordLayer(new TlsRecordLayer(context));

    }

    /**
     * Test of sendRawBytes method, of class TlsAttackerSocket.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSendRawBytes() throws Exception {
        socket.sendRawBytes(new byte[] { 1, 2, 3 });
        assertArrayEquals(new byte[] { 1, 2, 3 }, transportHandler.getSendByte());
    }

    /**
     * Test of receiveRawBytes method, of class TlsAttackerSocket.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testReceiveRawBytes() throws Exception {
        transportHandler.setFetchableByte(new byte[] { 1, 2, 3 });
        byte[] received = socket.receiveRawBytes();
        assertArrayEquals(new byte[] { 1, 2, 3 }, received);
    }

    /**
     * Test of send method, of class TlsAttackerSocket.
     *
     * @throws java.io.IOException
     */
    @Test
    public void testSend_String() throws IOException {
        socket.send("test");
        byte[] sentBytes = transportHandler.getSendByte();
        assertArrayEquals(
                sentBytes,
                ArrayConverter.concatenate(new byte[] { 0x17, 0x03, 0x03, 0x00, 0x04 },
                        "test".getBytes(Charset.forName("ASCII"))));
    }

    /**
     * Test of send method, of class TlsAttackerSocket.
     */
    @Test
    public void testSend_byteArr() {
        socket.send(new byte[] { 0, 1, 2, 3 });
        byte[] sentBytes = transportHandler.getSendByte();
        assertArrayEquals(sentBytes, new byte[] { 0x17, 0x03, 0x03, 0x00, 0x04, 0, 1, 2, 3 });
    }

    /**
     * Test of receiveBytes method, of class TlsAttackerSocket.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testReceiveBytes() throws Exception {
        transportHandler.setFetchableByte(new byte[] { 0x17, 0x03, 0x03, 0x00, 0x03, 8, 8, 8 });
        byte[] receivedBytes = socket.receiveBytes();
        assertArrayEquals(receivedBytes, new byte[] { 8, 8, 8 });
    }

    /**
     * Test of receiveString method, of class TlsAttackerSocket.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testReceiveString() throws Exception {
        transportHandler.setFetchableByte(ArrayConverter.concatenate(new byte[] { 0x17, 0x03, 0x03, 0x00, 0x04 },
                "test".getBytes(Charset.forName("ASCII"))));
        String receivedString = socket.receiveString();
        assertEquals("test", receivedString);
    }

}
