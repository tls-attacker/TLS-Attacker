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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
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

    /** A reply that read successfully but has the wrong status code is not executed-as-planned. */
    @Test
    public void testMismatchingReplyIsNotExecutedAsPlanned() {
        feed("502 Command not implemented\r\n");
        ReceiveRegexAsciiAction action = new ReceiveRegexAsciiAction("^234");
        action.execute(state);
        assertTrue(action.isExecuted());
        assertFalse(action.executedAsPlanned());
    }

    /** The default constructor uses US-ASCII so callers need not pass an encoding. */
    @Test
    public void testDefaultEncoding() {
        ReceiveRegexAsciiAction action = new ReceiveRegexAsciiAction("^220");
        assertEquals(AsciiAction.DEFAULT_ENCODING, action.getEncoding());
    }

    /**
     * The action carries STOP_TRACE_ON_FAILURE so a refused STARTTLS upgrade aborts the trace
     * immediately, without needing the global stopTraceAfterUnexpected config flag (which would
     * also abort the subsequent TLS handshake on any unexpected message).
     */
    @Test
    public void testStopTraceOnFailureOptionIsSet() {
        assertTrue(
                new ReceiveRegexAsciiAction("^234")
                        .getActionOptions()
                        .contains(ActionOption.STOP_TRACE_ON_FAILURE));
        assertTrue(
                new ReceiveRegexAsciiAction("^234", "UTF-8")
                        .getActionOptions()
                        .contains(ActionOption.STOP_TRACE_ON_FAILURE));
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
}
