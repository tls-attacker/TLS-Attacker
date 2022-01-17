/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.task;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;

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
    public boolean execute() {

        WorkflowExecutor executor =
            WorkflowExecutorFactory.createWorkflowExecutor(state.getConfig().getWorkflowExecutorType(), state);
        if (getBeforeTransportPreInitCallback() != null) {
            executor.setBeforeTransportPreInitCallback(getBeforeTransportPreInitCallback());
        }
        if (getBeforeTransportInitCallback() != null) {
            executor.setBeforeTransportInitCallback(getBeforeTransportInitCallback());
        }
        if (getAfterTransportInitCallback() != null) {
            executor.setAfterTransportInitCallback(getAfterTransportInitCallback());
        }
        if (getAfterExecutionCallback() != null) {
            executor.setAfterExecutionCallback(getAfterExecutionCallback());
        }
        executor.executeWorkflow();
        if (state.getContext().getTlsContext().isReceivedTransportHandlerException()) {
            throw new RuntimeException("TransportHandler exception received.");
        }
        return true;
    }

    public State getState() {
        return state;
    }

    @Override
    public void reset() {
        state.reset();
    }
}
