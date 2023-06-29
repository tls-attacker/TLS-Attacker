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
        State s = new State();
        assertNotNull(s.getConfig());
        assertNotNull(s.getWorkflowTrace());
        assertNotNull(s.getContext());
        // TODO: assertThat(workflowTrace.getType(),
        // isEqual(config.getWorkflowTraceType());
    }

    @Test
    public void initWithoutWorkflowTraceFailsProperly() {
        Config config = Config.createConfig();
        config.setWorkflowTraceType(null);

        ConfigurationException exception =
                assertThrows(ConfigurationException.class, () -> new State(config));
        assertTrue(exception.getMessage().startsWith("Could not load workflow trace"));
    }

    @Test
    public void initFromGoodConfig() {
        String expected = "testInitFromConfig";
        Config config = Config.createConfig();
        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        config.setDefaultApplicationMessageData(expected);
        State s = new State(config);
        assertNotNull(s.getConfig());
        assertEquals(s.getConfig(), config);
        assertNotNull(s.getWorkflowTrace());
        assertNotNull(s.getContext());
        assertEquals(config.getDefaultApplicationMessageData(), expected);
        // TODO: assertThat(workflowTrace.getType(),
        // isEqual(WorkflowTraceType.SHORT_HELLO));
    }

    @Test
    public void initFromConfigAndWorkflowTrace() {
        String expected = "testInitFromConfig";
        Config config = Config.createConfig();
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
        State s = new State(trace);

        ConfigurationException exception =
                assertThrows(ConfigurationException.class, s::getTlsContext);
        assertEquals(
                "getContext requires an alias if multiple contexts are defined",
                exception.getMessage());
    }

    @Test
    public void settingSingleContextWorkflowWithUnsupportedModeFails() {
        Config config = Config.createConfig();
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
        TlsContext origCtx = state.getTlsContext();
        TlsContext newCtx = new TlsContext();
        newCtx.setConnection(origCtx.getConnection());
        origCtx.setSelectedCipherSuite(CipherSuite.TLS_FALLBACK_SCSV);
        newCtx.setSelectedCipherSuite(CipherSuite.TLS_AES_128_CCM_SHA256);

        assertSame(CipherSuite.TLS_FALLBACK_SCSV, state.getTlsContext().getSelectedCipherSuite());
        state.replaceContext(newCtx.getContext());
        assertNotSame(state.getTlsContext(), origCtx);
        assertSame(
                CipherSuite.TLS_AES_128_CCM_SHA256, state.getTlsContext().getSelectedCipherSuite());
    }

    @Test
    public void changingValidTlsContextInMultiContextStateSucceeds() {
        WorkflowTrace trace = new WorkflowTrace();
        String conAlias1 = "con1";
        String conAlias2 = "con2";
        trace.addConnection(new OutboundConnection(conAlias1));
        trace.addConnection(new InboundConnection(conAlias2));
        State state = new State(trace);
        TlsContext origCtx1 = state.getContext(conAlias1).getTlsContext();
        TlsContext newCtx = new TlsContext();
        newCtx.setConnection(origCtx1.getConnection());
        origCtx1.setSelectedCipherSuite(CipherSuite.TLS_FALLBACK_SCSV);
        newCtx.setSelectedCipherSuite(CipherSuite.TLS_AES_128_CCM_SHA256);

        assertSame(
                CipherSuite.TLS_FALLBACK_SCSV,
                state.getTlsContext(conAlias1).getSelectedCipherSuite());
        state.replaceContext(newCtx.getContext());
        assertNotSame(state.getTlsContext(conAlias1), origCtx1);
        assertSame(
                CipherSuite.TLS_AES_128_CCM_SHA256,
                state.getTlsContext(conAlias1).getSelectedCipherSuite());
    }

    @Test
    public void replacingTlsContextWithBadAliasFails() {
        State state = new State();
        TlsContext origCtx = state.getTlsContext();
        TlsContext newCtx = new TlsContext();
        newCtx.setConnection(new InboundConnection("NewAlias"));

        ConfigurationException exception =
                assertThrows(
                        ConfigurationException.class,
                        () -> state.replaceContext(newCtx.getContext()));
        assertTrue(exception.getMessage().startsWith("No Context to replace for alias"));
    }

    @Test
    public void replacingTlsContextWithBadConnectionFails() {
        State state = new State();
        TlsContext origCtx = state.getTlsContext();
        TlsContext newCtx = new TlsContext();
        newCtx.setConnection(new InboundConnection(origCtx.getConnection().getAlias(), 87311));

        ContextHandlingException exception =
                assertThrows(
                        ContextHandlingException.class,
                        () -> state.replaceContext(newCtx.getContext()));
        assertEquals(
                "Cannot replace Context because the new Context defines another connection.",
                exception.getMessage());
    }
}
