/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.IOException;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DefaultWorkflowExecutor extends WorkflowExecutor {

    public DefaultWorkflowExecutor(State state) {
        super(WorkflowExecutorType.DEFAULT, state);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {

        if (config.isWorkflowExecutorShouldOpen()) {
            for (TlsContext ctx : state.getTlsContexts().values()) {
                ctx.initTransportHandler();
            }
        }

        for (TlsContext ctx : state.getTlsContexts().values()) {
            ctx.initRecordLayer();
        }

        state.getWorkflowTrace().reset();

        List<TLSAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        for (TLSAction action : tlsActions) {
            try {
                if (!(state.getConfig().isStopActionsAfterFatal() && isReceivedFatalAlert())) {
                    action.execute(state);
                } else {
                    LOGGER.trace("Skipping all Actions, received FatalAlert, StopActionsAfterFatal active");
                    break;
                }
            } catch (IOException | PreparationException ex) {
                throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
            }
        }

        if (state.getConfig().isWorkflowExecutorShouldClose()) {
            for (TlsContext ctx : state.getTlsContexts().values()) {
                try {
                    ctx.getTransportHandler().closeConnection();
                } catch (IOException ex) {
                    LOGGER.warn("Could not close connection for context " + ctx);
                    LOGGER.debug(ex);
                }
            }
        }

        if (state.getConfig().isResetWorkflowtracesBeforeSaving()) {
            state.getWorkflowTrace().reset();
        }
        storeTrace(state.getTlsContext());
    }

    /**
     * Check if a at least one TLS context received a fatal alert.
     */
    private boolean isReceivedFatalAlert() {
        for (TlsContext ctx : state.getTlsContexts().values()) {
            if (ctx.isReceivedFatalAlert()) {
                return true;
            }
        }
        return false;
    }
}
