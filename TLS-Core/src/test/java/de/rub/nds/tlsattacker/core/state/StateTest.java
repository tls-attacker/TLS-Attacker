/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.ContextHandlingException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import org.junit.jupiter.api.Test;

public class StateTest {

    @Test
    public void emptyInitUsesWorkflowTraceTypeFromConfig() {
        State state = new State();
        assertNotNull(state.getConfig());
        assertNotNull(state.getWorkflowTrace());
        assertNotNull(state.getContext());
    }

    @Test
    public void initWithoutWorkflowTraceFailsProperly() {
        Config config = new Config();
        config.setWorkflowTraceType(null);

        ConfigurationException exception =
                assertThrows(ConfigurationException.class, () -> new State(config));
        assertTrue(exception.getMessage().startsWith("Could not load workflow trace"));
    }

    @Test
    public void initFromGoodConfig() {
        String expected = "testInitFromConfig";
        Config config = new Config();
        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        config.setDefaultApplicationMessageData(expected);
        State state = new State(config);
        assertNotNull(state.getConfig());
        assertEquals(state.getConfig(), config);
        assertNotNull(state.getWorkflowTrace());
        assertNotNull(state.getContext());
        assertEquals(config.getDefaultApplicationMessageData(), expected);
    }

    @Test
    public void initFromConfigAndWorkflowTrace() {
        String expected = "testInitFromConfig";
        Config config = new Config();
        config.setDefaultApplicationMessageData(expected);
        WorkflowTrace trace = new WorkflowTrace();
        State s = new State(config, trace);
        assertNotNull(s.getConfig());
        assertEquals(s.getConfig(), config);
        assertEquals(config.getDefaultApplicationMessageData(), expected);

        assertNotNull(s.getWorkflowTrace());
        assertNotNull(s.getContext());

        assertEquals(s.getContext().getConnection(), trace.getConnections().get(0));
    }

    /** Assure that connection aliases are unique. */
    @Test
    public void settingDifferentConnectionsWithSameAliasFails() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new OutboundConnection("conEnd1"));
        trace.addConnection(new InboundConnection("conEnd1"));

        ConfigurationException exception =
                assertThrows(ConfigurationException.class, () -> new State(trace));
        assertEquals(
                "Workflow trace not well defined. Trace contains connections with the same alias",
                exception.getMessage());
    }

    /**
     * Prevent accidental misuse of single/default context getter. If multiple contexts are defined,
     * require the user to specify an alias to get the appropriate context.
     */
    @Test
    public void getContextRequiresAliasForMultipleDefinedContexts() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new OutboundConnection("conEnd1"));
        trace.addConnection(new InboundConnection("conEnd2"));
        State state = new State(trace);

        ConfigurationException exception =
                assertThrows(ConfigurationException.class, state::getTlsContext);
        assertEquals(
                "getContext requires an alias if multiple contexts are defined",
                exception.getMessage());
    }

    @Test
    public void settingSingleContextWorkflowWithUnsupportedModeFails() {
        Config config = new Config();
        config.setDefaultRunningMode(RunningModeType.MITM);
        config.setWorkflowTraceType(WorkflowTraceType.HELLO);

        ConfigurationException exception =
                assertThrows(ConfigurationException.class, () -> new State(config));
        assertEquals(
                "This workflow can only be configured for modes CLIENT and SERVER, but actual mode was MITM",
                exception.getMessage());
    }

    @Test
    public void dynamicallyChangingValidTlsContextSucceeds() {
        State state = new State();
        TlsContext originalContext = state.getTlsContext();
        TlsContext newContext =
                new Context(new State(new Config()), new InboundConnection()).getTlsContext();
        newContext.setConnection(originalContext.getConnection());
        originalContext.setSelectedCipherSuite(CipherSuite.TLS_FALLBACK_SCSV);
        newContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_CCM_SHA256);

        assertSame(CipherSuite.TLS_FALLBACK_SCSV, state.getTlsContext().getSelectedCipherSuite());
        state.replaceContext(newContext.getContext());
        assertNotSame(state.getTlsContext(), originalContext);
        assertSame(
                CipherSuite.TLS_AES_128_CCM_SHA256, state.getTlsContext().getSelectedCipherSuite());
    }

    @Test
    public void changingValidTlsContextInMultiContextStateSucceeds() {
        WorkflowTrace trace = new WorkflowTrace();
        String connectionAlias1 = "con1";
        String connectionAlias2 = "con2";
        trace.addConnection(new OutboundConnection(connectionAlias1));
        trace.addConnection(new InboundConnection(connectionAlias2));
        State state = new State(trace);
        TlsContext origContext = state.getContext(connectionAlias1).getTlsContext();
        TlsContext newContext =
                new Context(new State(new Config()), new InboundConnection()).getTlsContext();
        newContext.setConnection(origContext.getConnection());
        origContext.setSelectedCipherSuite(CipherSuite.TLS_FALLBACK_SCSV);
        newContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_CCM_SHA256);

        assertSame(
                CipherSuite.TLS_FALLBACK_SCSV,
                state.getTlsContext(connectionAlias1).getSelectedCipherSuite());
        state.replaceContext(newContext.getContext());
        assertNotSame(state.getTlsContext(connectionAlias1), origContext);
        assertSame(
                CipherSuite.TLS_AES_128_CCM_SHA256,
                state.getTlsContext(connectionAlias1).getSelectedCipherSuite());
    }

    @Test
    public void replacingTlsContextWithBadAliasFails() {
        State state = new State();
        TlsContext newContext =
                new Context(new State(new Config()), new InboundConnection()).getTlsContext();
        newContext.setConnection(new InboundConnection("NewAlias"));

        ConfigurationException exception =
                assertThrows(
                        ConfigurationException.class,
                        () -> state.replaceContext(newContext.getContext()));
        assertTrue(exception.getMessage().startsWith("No Context to replace for alias"));
    }

    @Test
    public void replacingTlsContextWithBadConnectionFails() {
        State state = new State();
        TlsContext origContext = state.getTlsContext();
        TlsContext newContext =
                new Context(new State(new Config()), new InboundConnection()).getTlsContext();
        newContext.setConnection(
                new InboundConnection(origContext.getConnection().getAlias(), 87311));

        ContextHandlingException exception =
                assertThrows(
                        ContextHandlingException.class,
                        () -> state.replaceContext(newContext.getContext()));
        assertEquals(
                "Cannot replace Context because the new Context defines another connection.",
                exception.getMessage());
    }
}
