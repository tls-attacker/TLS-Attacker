/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.task;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import java.util.concurrent.Callable;

/**
 * Do not use this Task if you want to rely on the socket state
 */
public class StateExecutionTask extends TlsTask {

    private final State state;

    private Callable<Integer> beforeConnectCallback = () -> {
        return 0;
    };

    public StateExecutionTask(State state, int reexecutions) {
        super(reexecutions);
        this.state = state;
    }

    @Override
    public boolean execute() {
        beforeConnectAction();
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
        if (state.getTlsContext().isReceivedTransportHandlerException()) {
            throw new RuntimeException("TransportHandler exception received.");
        }
        return true;
    }

    private void beforeConnectAction() {
        try {
            beforeConnectCallback.call();
        } catch (Exception ex) {
        }
    }

    public Callable<Integer> getBeforeConnectCallback() {
        return beforeConnectCallback;
    }

    public void setBeforeConnectCallback(Callable<Integer> beforeConnectCallback) {
        this.beforeConnectCallback = beforeConnectCallback;
    }

    public State getState() {
        return state;
    }

    @Override
    public void reset() {
        state.reset();
    }
}
