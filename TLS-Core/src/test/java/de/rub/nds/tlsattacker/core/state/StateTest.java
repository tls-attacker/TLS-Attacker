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
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import java.util.Map;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class StateTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    /**
     * Check if parameterless initialization behaves properly. Using this
     * initialization method is expected to result in loading the default config
     * but keeping the workflow trace unset. Consequently, there shouldn't be
     * any TLS contexts, too.
     */
    @Test
    public void testInitNoParameters() {
        State s = new State();
        assertNotNull(s.getConfig());
        assertNull(s.getWorkflowTrace());
        exception.expect(ConfigurationException.class);
        exception.expectMessage("No context defined, perhaps because no workflow trace is loaded yet");
        assertNull(s.getTlsContext());
    }

    /**
     * Check if initialization from config behaves properly. Should keeping the
     * workflow trace unset. Consequently, there shouldn't be any TLS contexts,
     * too.
     */
    @Test
    public void testInitFromConfig() {
        String expected = "testInitFromConfig";
        Config config = Config.createConfig();
        config.setDefaultApplicationMessageData(expected);
        State s = new State(config);
        assertNotNull(s.getConfig());
        assertEquals(s.getConfig(), config);
        assertEquals(config.getDefaultApplicationMessageData(), expected);

        assertNull(s.getWorkflowTrace());
        exception.expect(ConfigurationException.class);
        exception.expectMessage("No context defined, perhaps because no workflow trace is loaded yet");
        assertNull(s.getTlsContext());
    }

    /**
     * Check if initialization from config and workflow trace behaves properly.
     * Corresponding TLS contexts should be generated.
     */
    @Test
    public void testInitFromConfigAndWorkflowTrace() {
        String expected = "testInitFromConfig";
        Config config = Config.createConfig();
        config.setDefaultApplicationMessageData(expected);
        WorkflowTrace trace = new WorkflowTrace(config);
        State s = new State(config, trace);
        assertNotNull(s.getConfig());
        assertEquals(s.getConfig(), config);
        assertEquals(config.getDefaultApplicationMessageData(), expected);

        assertNotNull(s.getWorkflowTrace());
        assertNotNull(s.getTlsContext());

        assertEquals(s.getTlsContext().getConnectionEnd(), trace.getConnectionEnds().get(0));
    }

    /**
     * Be thorough with the context map and make sure that it can only be
     * modified via methods provided by State.
     */
    @Test
    public void testImmutableContextList() {
        Config config = Config.createConfig();
        WorkflowTrace trace = new WorkflowTrace(config);
        State s = new State(config, trace);

        TlsContext ctx = new TlsContext();
        Map<String, TlsContext> cMap = s.getTlsContexts();
        exception.expect(UnsupportedOperationException.class);
        cMap.put("ctxAlias", ctx);
    }

    /**
     * Assure that aliases are unique.
     */
    @Test
    public void testDuplicateAlias() {
        State s = new State();
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnectionEnd(new ClientConnectionEnd("conEnd1"));
        trace.addConnectionEnd(new ServerConnectionEnd("conEnd1"));

        exception.expect(ConfigurationException.class);
        exception.expectMessage("Connection end alias already in use:");
        s.setWorkflowTrace(trace);
    }

    /**
     * Prevent accidental misuse of single/default context getter. If multiple
     * contexts are defined, require the user to specify an alias to get the
     * appropriate context.
     */
    @Test
    public void testGetContextAliasRequired() {
        State s = new State();
        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnectionEnd(new ClientConnectionEnd("conEnd1"));
        trace.addConnectionEnd(new ServerConnectionEnd("conEnd2"));
        s.setWorkflowTrace(trace);

        exception.expect(ConfigurationException.class);
        exception.expectMessage("getTlsContext requires an alias if multiple contexts are defined");
        TlsContext c = s.getTlsContext();
    }

}
