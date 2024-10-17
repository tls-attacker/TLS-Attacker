/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DTLSWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    public DTLSWorkflowExecutor(State state) {
        super(WorkflowExecutorType.DTLS, state);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        LOGGER.debug("Starting execution of WorkflowTrace");
        if (config.isWorkflowExecutorShouldOpen()) {
            try {
                initAllLayer();
            } catch (IOException ex) {
                throw new WorkflowExecutionException(
                        "Workflow not executed, could not initialize transport handler: ", ex);
            }
        }
        state.getWorkflowTrace().reset();
        state.setStartTimestamp(System.currentTimeMillis());
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        int index = 0;
        while (index < tlsActions.size()) {
            TlsAction action = tlsActions.get(index);
            if (!action.isExecuted()) {
                LOGGER.trace("Executing regular action {} at index {}", action, index);
                try {
                    action.execute(state);
                } catch (UnsupportedOperationException E) {
                    LOGGER.warn("Unsupported operation!", E);
                    state.setExecutionException(E);
                } catch (PreparationException | WorkflowExecutionException ex) {
                    state.setExecutionException(ex);
                    throw new WorkflowExecutionException(
                            "Problem while executing Action:" + action.toString(), ex);
                } catch (Exception e) {
                    state.setExecutionException(e);
                    throw e;
                } finally {
                    state.setEndTimestamp(System.currentTimeMillis());
                }
            }

            if ((config.isStopActionsAfterFatal() && isReceivedFatalAlert())) {
                LOGGER.debug(
                        "Skipping all Actions, received FatalAlert, StopActionsAfterFatal active");
                break;
            }
            if ((config.getStopActionsAfterWarning() && isReceivedWarningAlert())) {
                LOGGER.debug(
                        "Skipping all Actions, received Warning Alert, StopActionsAfterWarning active");
                break;
            }
            if ((config.getStopActionsAfterIOException() && isIoException())) {
                LOGGER.debug(
                        "Skipping all Actions, received IO Exception, StopActionsAfterIOException active");
                break;
            }

            if (!action.executedAsPlanned()) {

                if (config.isStopTraceAfterUnexpected()) {
                    LOGGER.debug("Skipping all Actions, action did not execute as planned.");
                    break;
                } else {
                    LOGGER.debug("Action did not execute as planned. Moving on.");
                    index++;
                }
            } else {
                index++;
            }
        }

        if (config.isFinishWithCloseNotify()) {
            for (Context context : state.getAllContexts()) {
                int currentEpoch = context.getTlsContext().getRecordLayer().getWriteEpoch();
                for (int epoch = currentEpoch; epoch >= 0; epoch--) {
                    context.getTlsContext().getRecordLayer().setWriteEpoch(epoch);
                    sendCloseNotify(context.getTlsContext());
                }
                context.getTlsContext().getRecordLayer().setWriteEpoch(currentEpoch);
            }
        }

        setFinalSocketState();

        if (config.isWorkflowExecutorShouldClose()) {
            closeConnection();
        }
        if (config.isResetWorkflowTracesBeforeSaving()) {
            LOGGER.debug("Resetting WorkflowTrace");
            state.getWorkflowTrace().reset();
        }

        if (getAfterExecutionCallback() != null) {
            LOGGER.debug("Executing AfterExecutionCallback");
            try {
                getAfterExecutionCallback().apply(state);
            } catch (Exception ex) {
                LOGGER.trace("Error during AfterExecutionCallback", ex);
            }
        }
    }
}
