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
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Protocol-independent behaviour of {@link ReceiveRegexTextAction}: marshaling, encoding defaults,
 * reset, and the reassemble/fail-fast semantics for replies split across several TCP reads.
 *
 * <p>The replies here are deliberately not valid in any application protocol, so that these tests
 * describe the matching mechanism alone. Real status codes and their meaning belong in the
 * per-protocol tests, e.g. {@link ReceiveRegexTextActionFtpTest}.
 */
public class ReceiveRegexTextActionTest {

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

    /**
     * Installs a transport handler that returns each fragment on a separate fetchData() call, then
     * empty arrays, simulating a reply split across several TCP reads. Returns a single-element
     * counter holding the number of fetchData() calls served, so tests can assert how much of the
     * reply was drained.
     */
    private int[] feedChunks(String... asciiChunks) {
        Deque<byte[]> chunks = new ArrayDeque<>();
        for (String chunk : asciiChunks) {
            chunks.add(chunk.getBytes(StandardCharsets.US_ASCII));
        }
        int[] fetchCount = {0};
        context.setTransportHandler(
                new FakeTcpTransportHandler(ConnectionEndType.CLIENT) {
                    @Override
                    public byte[] fetchData() {
                        fetchCount[0]++;
                        byte[] next = chunks.poll();
                        return next != null ? next : new byte[0];
                    }
                });
        return fetchCount;
    }

    /**
     * An action left at its default encoding marshals to a bare {@code <ReceiveRegexText/>}
     * element, i.e. the default US-ASCII encoding is suppressed from the XML.
     */
    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testMarshalingEmptyActionYieldsMinimalOutput() {
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(ReceiveRegexTextAction.class);
    }

    /**
     * A hand-written bare {@code <ReceiveRegexText/>} element (no encoding) must round-trip back to
     * XML without the default encoding leaking in: reading it and writing it out again must not
     * introduce an {@code <encoding>US-ASCII</encoding>} element, while the effective encoding
     * still resolves to the default at runtime.
     */
    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testEmptyElementRoundTripsWithoutEncoding() throws Exception {
        String bareElement = "<ReceiveRegexText/>";

        TlsAction read =
                ActionIO.read(
                        new ByteArrayInputStream(bareElement.getBytes(StandardCharsets.UTF_8)));
        SilentByteArrayOutputStream out = new SilentByteArrayOutputStream();
        ActionIO.write(out, read);
        String written = out.toString(StandardCharsets.UTF_8);

        assertFalse(
                written.contains("<encoding>"),
                "Round-tripped bare element must not gain an <encoding> element, but was:\n"
                        + written);
        assertEquals(TextAction.DEFAULT_ENCODING, ((ReceiveRegexTextAction) read).getEncoding());
    }

    /** A reply matching the regex counts as executed-as-planned. */
    @Test
    public void testMatchingReplyIsExecutedAsPlanned() {
        feed("MATCH rest of line\r\n");
        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^MATCH");
        action.execute(state);
        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());
        assertEquals("MATCH rest of line\r\n", action.getReceivedText());
    }

    /** A reply that can never match the regex aborts the trace. */
    @Test
    public void testMismatchingReplyAbortsTrace() {
        feed("NOMATCH rest of line\r\n");
        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^MATCH");
        assertThrows(WorkflowExecutionException.class, () -> action.execute(state));
        assertFalse(action.executedAsPlanned());
    }

    /** The default constructor uses US-ASCII so callers need not pass an encoding. */
    @Test
    public void testDefaultEncoding() {
        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^MATCH");
        assertEquals(TextAction.DEFAULT_ENCODING, action.getEncoding());
    }

    /** reset() clears the received text and execution flag so the action can run again. */
    @Test
    public void testReset() {
        feed("MATCH rest of line\r\n");
        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^MATCH");
        action.execute(state);
        assertTrue(action.isExecuted());

        action.reset();
        assertFalse(action.isExecuted());
        assertEquals(null, action.getReceivedText());
    }

    /**
     * A reply split across several TCP reads is reassembled: while the accumulated text is still a
     * viable prefix of the pattern the action keeps reading, and matches once the rest arrives.
     */
    @Test
    public void testFragmentedMatchingReplyIsReassembled() {
        feedChunks("MAT", "CH rest of line\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^MATCH");
        action.execute(state);

        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());
        assertEquals("MATCH rest of line\r\n", action.getReceivedText());
    }

    /**
     * When the pattern already matches on the first fragment but the rest of the line arrives in a
     * later packet, the action keeps reading until the full line is drained. Stopping at the first
     * prefix match would leave the trailing bytes in the socket and corrupt the following TLS
     * handshake.
     */
    @Test
    public void testMatchingPrefixStillDrainsRestOfLine() {
        int[] fetchCount = feedChunks("MATCH", " rest of line\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^MATCH");
        action.execute(state);

        assertTrue(action.executedAsPlanned());
        assertEquals("MATCH rest of line\r\n", action.getReceivedText());
        // Both fragments must have been consumed so nothing leaks into the handshake.
        assertEquals(2, fetchCount[0]);
    }

    /**
     * A reply that diverges from the pattern aborts the whole trace as soon as it can no longer
     * match, without waiting for the remaining fragments.
     */
    @Test
    public void testFragmentedDivergingReplyFailsFast() {
        int[] fetchCount = feedChunks("NO", "MATCH rest of line\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^MATCH");

        // Once "NO" can never match /^MATCH/ the action aborts the trace instead of silently
        // proceeding into the TLS handshake.
        assertThrows(WorkflowExecutionException.class, () -> action.execute(state));
        // The second fragment must not have been read.
        assertEquals("NO", action.getReceivedText());
        assertEquals(1, fetchCount[0]);
    }
}
