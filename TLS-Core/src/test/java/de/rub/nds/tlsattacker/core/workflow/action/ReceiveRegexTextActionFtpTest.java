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

import de.rub.nds.tlsattacker.core.exceptions.StarttlsNotSupportedException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * FTP STARTTLS (RFC 4217) status replies driven through {@link ReceiveRegexTextAction}: the 220
 * greeting and the 234 / 5xx answers to AUTH TLS. Encoding, marshaling and fragment-reassembly
 * semantics are protocol-independent and covered by {@link ReceiveRegexTextActionTest}.
 */
public class ReceiveRegexTextActionFtpTest {

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
     * The actions as {@link
     * de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory} builds them: the
     * pattern names the final line by its space after the status code, and a 4xx/5xx final line
     * aborts.
     */
    private static ReceiveRegexTextAction authTlsReply() {
        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^234 ");
        action.setAbortRegex("^[45]\\d\\d ");
        return action;
    }

    /** The 220 service-ready greeting the server sends before any command. */
    @Test
    public void testGreetingIsAccepted() {
        feed("220 Welcome to FTP server\r\n");
        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^220 ");
        action.execute(state);
        assertTrue(action.executedAsPlanned());
        assertEquals("220 Welcome to FTP server\r\n", action.getReceivedText());
    }

    /**
     * RFC 959 lets the greeting span several lines, marking continuations with a hyphen after the
     * code and the final line with a space. The whole greeting must be drained, or what is left of
     * it is parsed as a TLS record once the handshake starts.
     */
    @Test
    public void testMultilineGreetingIsDrained() {
        feed("220-Welcome to FTP server\r\n220-Unauthorized access prohibited\r\n220 Ready\r\n");
        ReceiveRegexTextAction action = new ReceiveRegexTextAction("^220 ");
        action.execute(state);
        assertTrue(action.executedAsPlanned());
        assertEquals(
                "220-Welcome to FTP server\r\n220-Unauthorized access prohibited\r\n220 Ready\r\n",
                action.getReceivedText());
    }

    /** 234 is the affirmative answer to AUTH TLS: the TLS handshake may start. */
    @Test
    public void testAuthTlsAcceptedReplyIsExecutedAsPlanned() {
        feed("234 AUTH TLS successful\r\n");
        ReceiveRegexTextAction action = authTlsReply();
        action.execute(state);
        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());
        assertEquals("234 AUTH TLS successful\r\n", action.getReceivedText());
    }

    /** A multiline 234 is accepted too, and read to its final line. */
    @Test
    public void testMultilineAuthTlsAcceptedReplyIsDrained() {
        feed("234-AUTH TLS OK\r\n234-continuation line\r\n234 End\r\n");
        ReceiveRegexTextAction action = authTlsReply();
        action.execute(state);
        assertTrue(action.executedAsPlanned());
        assertEquals(
                "234-AUTH TLS OK\r\n234-continuation line\r\n234 End\r\n",
                action.getReceivedText());
    }

    /**
     * A server without AUTH TLS support answers 502; the trace must abort rather than start a
     * handshake against a server that just refused to upgrade.
     */
    @Test
    public void testAuthTlsUnimplementedReplyAbortsTrace() {
        feed("502 Command not implemented\r\n");
        ReceiveRegexTextAction action = authTlsReply();
        assertThrows(StarttlsNotSupportedException.class, () -> action.execute(state));
        assertFalse(action.executedAsPlanned());
    }

    /** A server that refuses the security mechanism answers 534, which must also abort. */
    @Test
    public void testAuthTlsRejectedReplyAbortsTrace() {
        feed("534 Request denied for policy reasons\r\n");
        ReceiveRegexTextAction action = authTlsReply();
        assertThrows(StarttlsNotSupportedException.class, () -> action.execute(state));
        assertFalse(action.executedAsPlanned());
    }
}
