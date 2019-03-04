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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.security.Security;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class DefaultWorkflowExecutorTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int PORT = 443;
    private static final int TIMEOUT = 2000;
    private BasicTlsServer tlsServer;

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    public DefaultWorkflowExecutorTest() {
        Security.addProvider(new BouncyCastleProvider());
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
}
