/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.task;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;

/**
 * Do not use this Task if you want to rely on the socket state
 */
public class StateExecutionTask extends TlsTask {

    private final State state;

    public StateExecutionTask(State state, int reexecutions) {
        super(reexecutions);
        this.state = state;
    }

    @Override
    public void execute() {
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
    }

    public State getState() {
        return state;
    }

    @Override
    public void reset() {
        state.reset();
    }
}
