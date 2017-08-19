/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.Security;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.hamcrest.CoreMatchers.startsWith;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class DefaultWorkflowExecutorTest {

    private static final Logger LOGGER = LogManager.getLogger(DefaultWorkflowExecutorTest.class);
    private static final int PORT = 4433;
    private static final int TIMEOUT = 2000;
    private BasicTlsServer tlsServer;

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    public DefaultWorkflowExecutorTest() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Make sure that actions have a contextAlias if multiple contexts are
     * defined.
     */
    @Test
    public void testExecuteWorkflowActionsNeedAlias() {

        Config config = Config.createConfig();
        State state = new State(config);
        // TODO WIP remove the default context that's currently created
        // implicitly for ease of transition to multi context support. This
        // shouldn't be required in the future.
        state.clearTlsContexts();
        TlsContext c1 = new TlsContext(config);
        TlsContext c2 = new TlsContext(config);
        c1.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        c2.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        state.addTlsContext("ctx1", c1);
        state.addTlsContext("ctx2", c2);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ClientHelloMessage(state.getConfig())));
        state.setWorkflowTrace(trace);

        WorkflowExecutor workflowExecutor;
        workflowExecutor = new DefaultWorkflowExecutor(state);

        exception.expect(WorkflowExecutionException.class);
        exception.expectMessage(startsWith("Multiple connection ends/contexts defined,"
                + " but the following action has an empty context alias:"));
        workflowExecutor.executeWorkflow();
    }

    /**
     * Fallback to WorkflowConfigurationFactory with default context should
     * work.
     */
    @Test
    public void testExecuteImplicitWorkflowWithDefaultContexts() {

        Config config = Config.createConfig();
        config.setWorkflowTraceType(WorkflowTraceType.HELLO);
        State state = new State(config);

        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
    }

    /**
     * Fallback to WorkflowConfigurationFactory with multiple context is
     * expected to fail. This should fail since the WorkflowConfigurationFactory
     * doesn't know which context to use to construct the worfklow.
     */
    @Test
    public void testExecuteImplicitWorkflowWithMultipleContexts() {

        Config config = Config.createConfig();
        config.setWorkflowTraceType(WorkflowTraceType.HELLO);
        State state = new State(config);
        TlsContext c1 = new TlsContext(config);
        TlsContext c2 = new TlsContext(config);
        c1.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        c2.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        state.addTlsContext("ctx1", c1);
        state.addTlsContext("ctx2", c2);

        WorkflowExecutor workflowExecutor;
        exception.expect(ConfigurationException.class);
        exception.expectMessage("Can only configure workflow trace for"
                + " a single context, but multiple contexts are defined.");
        workflowExecutor = new DefaultWorkflowExecutor(state);
    }
}
