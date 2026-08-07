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

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.StarttlsNotSupportedException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * The action reads the capability list from the preceding text reply in the trace, so every test
 * builds a two-action trace: a {@link ReceiveRegexTextAction} fed a canned FTP FEAT reply, followed
 * by the assertion under test.
 */
public class AssertStartTlsCapabilityAdvertisedActionTest {

    private static final String FEAT_WITH_AUTH_TLS =
            "211-Features:\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n211 End\r\n";

    private static final String FEAT_WITHOUT_AUTH_TLS =
            "211-Features:\r\n PBSZ\r\n PROT\r\n UTF8\r\n211 End\r\n";

    /**
     * Runs a discovery reply through the action and returns the executed action, so the assertions
     * can inspect its outcome.
     */
    private static AssertStartTlsCapabilityAdvertisedAction executeAgainst(
            String discoveryReply, String capability) {
        State state = new State();
        TlsContext context = state.getTlsContext();
        context.setTransportHandler(new FakeTcpTransportHandler(ConnectionEndType.CLIENT));
        ((FakeTcpTransportHandler) context.getTransportHandler())
                .setFetchableByte(discoveryReply.getBytes(StandardCharsets.US_ASCII));

        ReceiveRegexTextAction discovery = new ReceiveRegexTextAction("^211 ");
        AssertStartTlsCapabilityAdvertisedAction assertion =
                new AssertStartTlsCapabilityAdvertisedAction(capability);
        WorkflowTrace trace = state.getWorkflowTrace();
        trace.addTlsAction(discovery);
        trace.addTlsAction(assertion);

        discovery.execute(state);
        assertion.execute(state);
        return assertion;
    }

    /** A feature list naming the capability lets the workflow continue to the upgrade command. */
    @Test
    public void testAdvertisedCapabilityIsAccepted() {
        AssertStartTlsCapabilityAdvertisedAction action =
                executeAgainst(FEAT_WITH_AUTH_TLS, "AUTH TLS");
        assertTrue(action.isExecuted());
        assertTrue(action.executedAsPlanned());
        assertTrue(action.isAdvertised());
    }

    /**
     * A server that answers the discovery command without offering the upgrade is taken at its
     * word: the trace aborts before the upgrade command is ever sent.
     */
    @Test
    public void testUnadvertisedCapabilityAbortsTrace() {
        assertThrows(
                StarttlsNotSupportedException.class,
                () -> executeAgainst(FEAT_WITHOUT_AUTH_TLS, "AUTH TLS"));
    }

    /** Capability names are matched case-insensitively, as the protocols specify them. */
    @Test
    public void testMatchIsCaseInsensitive() {
        AssertStartTlsCapabilityAdvertisedAction action =
                executeAgainst("211-Features:\r\n auth tls\r\n211 End\r\n", "AUTH TLS");
        assertTrue(action.executedAsPlanned());
    }

    /**
     * The capability must be a whole entry rather than a substring, or an unrelated feature that
     * merely contains the name would be read as an offer to upgrade.
     */
    @Test
    public void testSubstringOfAnotherCapabilityDoesNotMatch() {
        assertThrows(
                StarttlsNotSupportedException.class,
                () -> executeAgainst("211-Features:\r\n NOSTARTTLS\r\n211 End\r\n", "STARTTLS"));
    }

    /**
     * Without a preceding text reply there is no capability list to read, which is a usage error.
     */
    @Test
    public void testMissingDiscoveryReplyIsAnActionExecutionError() {
        State state = new State();
        AssertStartTlsCapabilityAdvertisedAction action =
                new AssertStartTlsCapabilityAdvertisedAction("AUTH TLS");
        state.getWorkflowTrace().addTlsAction(action);
        assertThrows(ActionExecutionException.class, () -> action.execute(state));
    }

    /** Executing twice is a usage error, matching the other actions. */
    @Test
    public void testDoubleExecutionIsRejected() {
        State state = new State();
        TlsContext context = state.getTlsContext();
        context.setTransportHandler(new FakeTcpTransportHandler(ConnectionEndType.CLIENT));
        ((FakeTcpTransportHandler) context.getTransportHandler())
                .setFetchableByte(FEAT_WITH_AUTH_TLS.getBytes(StandardCharsets.US_ASCII));

        ReceiveRegexTextAction discovery = new ReceiveRegexTextAction("^211 ");
        AssertStartTlsCapabilityAdvertisedAction action =
                new AssertStartTlsCapabilityAdvertisedAction("AUTH TLS");
        state.getWorkflowTrace().addTlsAction(discovery);
        state.getWorkflowTrace().addTlsAction(action);

        discovery.execute(state);
        action.execute(state);
        assertThrows(ActionExecutionException.class, () -> action.execute(state));
    }

    /** Resetting clears the outcome so the action can run again in a repeated workflow. */
    @Test
    public void testResetClearsOutcome() {
        AssertStartTlsCapabilityAdvertisedAction action =
                executeAgainst(FEAT_WITH_AUTH_TLS, "AUTH TLS");
        action.reset();
        assertFalse(action.executedAsPlanned());
        assertEquals(null, action.isAdvertised());
    }
}
