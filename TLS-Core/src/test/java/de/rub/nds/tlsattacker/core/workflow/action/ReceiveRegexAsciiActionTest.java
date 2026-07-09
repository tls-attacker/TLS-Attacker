/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.exception.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ReceiveRegexAsciiActionTest {

    private State state;
    private TlsContext context;

    @BeforeEach
    public void setUp() {
        state = new State();
        context = state.getTlsContext();
        context.setTransportHandler(new FakeTcpTransportHandler(ConnectionEndType.CLIENT));
    }

    private void feed(String reply) {
        ((FakeTcpTransportHandler) context.getTransportHandler())
                .setFetchableByte(reply.getBytes(StandardCharsets.US_ASCII));
    }

    /** A reply matching the status-code regex counts as executed-as-planned. */
    @Test
    public void testMatchingReplyIsExecutedAsPlanned() {
        feed("234 AUTH TLS successful\r\n");
        ReceiveRegexAsciiAction action = new ReceiveRegexAsciiAction("^234");
        action.execute(state);
        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());
        assertEquals("234 AUTH TLS successful\r\n", action.getReceivedAsciiString());
    }

    /** A reply with a wrong status code that can never match aborts the trace. */
    @Test
    public void testMismatchingReplyAbortsTrace() {
        feed("502 Command not implemented\r\n");
        ReceiveRegexAsciiAction action = new ReceiveRegexAsciiAction("^234");
        assertThrows(WorkflowExecutionException.class, () -> action.execute(state));
        assertFalse(action.executedAsPlanned());
    }

    /** The default constructor uses US-ASCII so callers need not pass an encoding. */
    @Test
    public void testDefaultEncoding() {
        ReceiveRegexAsciiAction action = new ReceiveRegexAsciiAction("^220");
        assertEquals(AsciiAction.DEFAULT_ENCODING, action.getEncoding());
    }

    /** reset() clears the received text and execution flag so the action can run again. */
    @Test
    public void testReset() {
        feed("220 Service ready\r\n");
        ReceiveRegexAsciiAction action = new ReceiveRegexAsciiAction("^220");
        action.execute(state);
        assertTrue(action.isExecuted());

        action.reset();
        assertFalse(action.isExecuted());
        assertEquals(null, action.getReceivedAsciiString());
    }

    /**
     * A status reply split across several TCP reads is reassembled: while the accumulated text is
     * still a viable prefix of the pattern the action keeps reading, and matches once the rest
     * arrives.
     */
    @Test
    public void testFragmentedMatchingReplyIsReassembled() {
        DripTransportHandler drip = new DripTransportHandler("23", "4 AUTH TLS successful\r\n");
        context.setTransportHandler(drip);

        ReceiveRegexAsciiAction action = new ReceiveRegexAsciiAction("^234");
        action.execute(state);

        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());
        assertEquals("234 AUTH TLS successful\r\n", action.getReceivedAsciiString());
    }

    /**
     * A reply that diverges from the pattern aborts the whole trace as soon as it can no longer
     * match, without waiting for the remaining fragments.
     */
    @Test
    public void testFragmentedDivergingReplyFailsFast() {
        DripTransportHandler drip = new DripTransportHandler("58", "0 error\r\n");
        context.setTransportHandler(drip);

        ReceiveRegexAsciiAction action = new ReceiveRegexAsciiAction("^234");

        // Once "58" can never match /^234/ the action aborts the trace instead of silently
        // proceeding into the TLS handshake.
        assertThrows(WorkflowExecutionException.class, () -> action.execute(state));
        // The second fragment must not have been read.
        assertEquals("58", action.getReceivedAsciiString());
        assertEquals(1, drip.getFetchCount());
    }

    /** Returns each configured chunk on a separate fetchData() call, then empty arrays. */
    private static final class DripTransportHandler extends FakeTcpTransportHandler {

        private final java.util.Deque<byte[]> chunks = new java.util.ArrayDeque<>();
        private int fetchCount = 0;

        DripTransportHandler(String... asciiChunks) {
            super(ConnectionEndType.CLIENT);
            for (String chunk : asciiChunks) {
                chunks.add(chunk.getBytes(StandardCharsets.US_ASCII));
            }
        }

        int getFetchCount() {
            return fetchCount;
        }

        @Override
        public byte[] fetchData() {
            fetchCount++;
            byte[] next = chunks.poll();
            return next != null ? next : new byte[0];
        }
    }
}
