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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.exceptions.StarttlsNotSupportedException;
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

    /**
     * A reply that does not match is read to the end of what the server sends and then reported as
     * not-as-planned. Without an abort pattern there is nothing to distinguish "wrong reply" from
     * "the line the pattern targets has not arrived yet", so the read cannot end early.
     */
    @Test
    public void testMismatchingReplyIsNotExecutedAsPlanned() {
        feed("NOMATCH rest of line\r\n");
        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^MATCH");
        action.execute(state);
        assertTrue(action.isExecuted());
        assertFalse(action.executedAsPlanned());
        assertEquals("NOMATCH rest of line\r\n", action.getReceivedText());
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
     * A pattern anchored to the start of a line is not satisfied by a match in the middle of one:
     * "NOMATCH" contains "MATCH", but not at a line start, so the reply is read to the end and
     * reported as not-as-planned.
     */
    @Test
    public void testMatchMustBeAtTheStartOfALine() {
        feedChunks("NO", "MATCH rest of line\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^MATCH");
        action.execute(state);

        assertTrue(action.isExecuted());
        assertFalse(action.executedAsPlanned());
        assertEquals("NOMATCH rest of line\r\n", action.getReceivedText());
    }

    /**
     * The read keeps going past the lines that do not match and stops on the one that does. Ending
     * at the first line would leave the rest of the reply in the socket.
     */
    @Test
    public void testReplyIsReadUntilTheMatchingLine() {
        int[] fetchCount = feedChunks("* FIRST\r\n", "* SECOND\r\n", "TAG OK done\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^TAG OK");
        action.execute(state);

        assertTrue(action.executedAsPlanned());
        assertEquals("* FIRST\r\n* SECOND\r\nTAG OK done\r\n", action.getReceivedText());
        assertEquals(3, fetchCount[0]);
    }

    /**
     * Leading lines that do not match are expected, since the pattern targets the terminating line.
     * Aborting on them would reject a perfectly good reply.
     */
    @Test
    public void testReplyDoesNotAbortOnLeadingLines() {
        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^TAG OK");
        feed("* NOMATCH at all\r\nTAG OK done\r\n");

        action.execute(state);

        assertTrue(action.executedAsPlanned());
    }

    /** A complete reply whose terminating line does not match is not executed as planned. */
    @Test
    public void testReplyWithMismatchingFinalLineIsNotExecutedAsPlanned() {
        feed("* FIRST\r\nTAG NO refused\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^TAG OK");
        action.execute(state);

        assertTrue(action.isExecuted());
        assertFalse(action.executedAsPlanned());
    }

    /**
     * A reply is only complete once the matching line has been terminated, so a pattern that
     * matches a prefix of the final line still drains the rest of it. Stopping early would leave
     * plaintext in the socket for the TLS handshake to trip over.
     */
    @Test
    public void testReplyDrainsRestOfMatchingLine() {
        int[] fetchCount = feedChunks("* FIRST\r\n", "TAG OK", " done\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^TAG OK");
        action.execute(state);

        assertTrue(action.executedAsPlanned());
        assertEquals("* FIRST\r\nTAG OK done\r\n", action.getReceivedText());
        assertEquals(3, fetchCount[0]);
    }

    /**
     * A block terminated by a lone dot, as NNTP uses (RFC 4642), is named directly by the pattern.
     * The whole block is read, so nothing of it is left for the handshake.
     */
    @Test
    public void testDotTerminatedBlockIsReadWhole() {
        feed("101 Capability list:\r\nVERSION 2\r\nSTARTTLS\r\n.\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^\\.$");
        action.execute(state);

        assertTrue(action.executedAsPlanned());
        assertEquals(
                "101 Capability list:\r\nVERSION 2\r\nSTARTTLS\r\n.\r\n", action.getReceivedText());
    }

    /**
     * SMTP marks continuation lines with a hyphen after the status code and the final line with a
     * space (RFC 3207), so the pattern names the space form to find the end of the reply.
     */
    @Test
    public void testSpaceAfterCodeEndsReply() {
        feed("250-mail.example.org\r\n250-PIPELINING\r\n250 STARTTLS\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^250 ");
        action.execute(state);

        assertTrue(action.executedAsPlanned());
        assertEquals(
                "250-mail.example.org\r\n250-PIPELINING\r\n250 STARTTLS\r\n",
                action.getReceivedText());
    }

    /** No abort pattern is configured by default, so nothing cuts the read short. */
    @Test
    public void testNoAbortRegexByDefault() {
        assertEquals(null, new ReceiveRegexTextAction("^MATCH").getAbortRegex());
    }

    /**
     * A reply matching the abort pattern ends the read on the packet that carries it, rather than
     * reading on until the socket times out. At crawler scale that is a full timeout saved per
     * refusing host.
     */
    @Test
    public void testAbortRegexStopsTheReadAtOnce() {
        int[] fetchCount = feedChunks("534 Policy requires SSL\r\n", "234 never read\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^234 ");
        action.setAbortRegex("^[45]\\d\\d ");

        assertThrows(StarttlsNotSupportedException.class, () -> action.execute(state));
        assertFalse(action.executedAsPlanned());
        assertEquals("534 Policy requires SSL\r\n", action.getReceivedText());
        // The second fragment must not have been read.
        assertEquals(1, fetchCount[0]);
    }

    /**
     * The abort pattern is only honoured on a terminated line, so a refusal split mid-line does not
     * fire it early and the rest of the line is still drained into the reported text.
     */
    @Test
    public void testAbortRegexWaitsForACompleteLine() {
        feedChunks("53", "4 Policy requires SSL\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^234 ");
        action.setAbortRegex("^[45]\\d\\d ");

        assertThrows(StarttlsNotSupportedException.class, () -> action.execute(state));
        assertEquals("534 Policy requires SSL\r\n", action.getReceivedText());
    }

    /**
     * The abort pattern must not fire on the continuation lines of a reply that is going to
     * succeed: it names what a refusal looks like, not "anything that is not the expected reply".
     */
    @Test
    public void testAbortRegexDoesNotFireOnContinuationLines() {
        feed("234-AUTH TLS OK\r\n234-continuation line\r\n234 End\r\n");

        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^234 ");
        action.setAbortRegex("^[45]\\d\\d ");
        action.execute(state);

        assertTrue(action.executedAsPlanned());
        assertEquals(
                "234-AUTH TLS OK\r\n234-continuation line\r\n234 End\r\n",
                action.getReceivedText());
    }

    /** The abort pattern takes part in equality. */
    @Test
    public void testEqualityAccountsForAbortRegex() {
        ReceiveRegexTextAction withAbort = new ReceiveRegexTextAction("^MATCH");
        withAbort.setAbortRegex("^[45]\\d\\d ");

        assertEquals(new ReceiveRegexTextAction("^MATCH"), new ReceiveRegexTextAction("^MATCH"));
        assertNotEquals(new ReceiveRegexTextAction("^MATCH"), withAbort);
    }
}
