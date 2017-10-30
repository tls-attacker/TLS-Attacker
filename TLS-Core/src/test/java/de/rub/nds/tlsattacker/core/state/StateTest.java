/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class StateTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    @Test
    public void emptyInitUsesWorklfowTraceTypeFromConfig() {
        State s = new State();
        assertNotNull(s.getConfig());
        assertNotNull(s.getWorkflowTrace());
        assertNotNull(s.getTlsContext());
        // TOOD: assertThat(workflowTrace.getType(),
        // isEqual(config.getWorklfowTraceType());
    }

    @Test
    public void initWithoutWorkflowTraceFailsProperly() {
        Config config = Config.createConfig();
        config.setWorkflowInput(null);
        config.setWorkflowTraceType(null);
        exception.expect(ConfigurationException.class);
        exception.expectMessage("Could not load WorkflowTrace. Both workflow_trace_type"
                + " and workflow_trace_input are unspecified.");
        State s = new State(config);
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
        assertNotNull(s.getTlsContext());
        assertEquals(config.getDefaultApplicationMessageData(), expected);
        // TOOD: assertThat(workflowTrace.getType(),
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
        assertNotNull(s.getTlsContext());

        assertEquals(s.getTlsContext().getConnection(), trace.getConnections().get(0));
    }

    /**
     * Assure that connection aliases are unique.
     */
    @Test
    public void settingDifferentConnectionsWithSameAliasFails() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new OutboundConnection("conEnd1"));
        trace.addConnection(new InboundConnection("conEnd1"));

        exception.expect(ConfigurationException.class);
        exception.expectMessage("Workflow trace not well defined. Trace contains" + " connections with the same alias");
        State s = new State(trace);
    }

    /**
     * Prevent accidental misuse of single/default context getter. If multiple
     * contexts are defined, require the user to specify an alias to get the
     * appropriate context.
     */
    @Test
    public void getContextRequiresAliasForMultipleDefinedContexts() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(new OutboundConnection("conEnd1"));
        trace.addConnection(new InboundConnection("conEnd2"));
        State s = new State(trace);

        exception.expect(ConfigurationException.class);
        exception.expectMessage("getTlsContext requires an alias if multiple contexts are defined");
        TlsContext c = s.getTlsContext();
    }

    @Test
    public void settingSingleContextWorkflowWithUnsupportedModeFails() {

        Config config = Config.createConfig();
        config.setDefaulRunningMode(RunningModeType.MITM);
        config.setWorkflowTraceType(WorkflowTraceType.HELLO);

        exception.expect(ConfigurationException.class);
        exception.expectMessage("This workflow can only be configured for modes CLIENT and "
                + "SERVER, but actual mode was MITM");
        State state = new State(config);
    }
}
