/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import org.junit.jupiter.api.Test;

public class DefaultWorkflowExecutorTest {

    /** Fallback to WorkflowConfigurationFactory with default context should work. */
    @Test
    public void testExecuteImplicitWorkflowWithDefaultContexts() {
        Config config = new Config();
        config.setWorkflowTraceType(WorkflowTraceType.HELLO);
        State state = new State(config);
        assertDoesNotThrow(() -> new DefaultWorkflowExecutor(state));
    }
}
