/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.task;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;

/** Do not use this Task if you want to rely on the socket state */
public class StateExecutionTask extends TlsTask {

    private final State state;

    public StateExecutionTask(State state, int reexecutions) {
        super(reexecutions);
        this.state = state;
    }

    @Override
    public boolean execute() {
        WorkflowExecutor executor = getExecutor(state);
        executor.executeWorkflow();
        if (state.getTlsContext().isReceivedTransportHandlerException()) {
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
