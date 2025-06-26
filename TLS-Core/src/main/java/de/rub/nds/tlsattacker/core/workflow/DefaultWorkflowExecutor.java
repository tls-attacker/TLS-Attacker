/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.exceptions.SkipActionException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DefaultWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    public DefaultWorkflowExecutor(State state) {
        super(WorkflowExecutorType.DEFAULT, state);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {

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
        TlsAction lastExecutedAction = null;
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        for (int i = 0; i < tlsActions.size(); i++) {
            TlsAction action = tlsActions.get(i);

            if ((config.isStopActionsAfterFatal() && isReceivedFatalAlert())) {
                LOGGER.debug(
                        "Skipping all Actions, received FatalAlert, StopActionsAfterFatal active");
                break;
            }
            if ((config.getStopReceivingAfterFatal()
                    && isReceivedFatalAlert()
                    && tlsActions instanceof ReceivingAction)) {
                LOGGER.debug(
                        "Skipping all ReceiveActions, received FatalAlert, StopActionsAfterFatal active");
                break;
            }
            if ((config.getStopActionsAfterWarning() && isReceivedWarningAlert())) {
                LOGGER.debug(
                        "Skipping all Actions, received Warning Alert, StopActionsAfterWarning active");
                break;
            }
            if ((config.getStopActionsAfterIOException() && isIoException())) {
                if (lastExecutedAction != null && lastExecutedAction instanceof SendingAction) {
                    LOGGER.debug(
                            "Received IO Exception with StopActionsAfterIOException active, skipping to next receive action to process pending message bytes.");
                    processPendingReceiveBufferBytes(i - 1);
                } else {
                    LOGGER.debug(
                            "Skipping all Actions, received IO Exception, StopActionsAfterIOException active");
                }
                break;
            }

            try {
                this.executeAction(action, state);
            } catch (SkipActionException ex) {
                continue;
            } finally {
                lastExecutedAction = action;
            }

            if (config.isStopTraceAfterUnexpected() && !action.executedAsPlanned()) {
                if (lastExecutedAction instanceof SendingAction) {
                    LOGGER.debug(
                            "SendingAction did not execute as planned, skipping to next receive action to process pending message bytes.");
                    processPendingReceiveBufferBytes(i);
                } else {
                    LOGGER.debug("Skipping all Actions, action did not execute as planned.");
                }
                break;
            }
        }

        if (config.isFinishWithCloseNotify()) {
            for (Context context : state.getAllContexts()) {
                sendCloseNotify(context.getTlsContext());
            }
        }

        setFinalSocketState();

        if (config.isWorkflowExecutorShouldClose()) {
            closeConnection();
        }

        if (state.getWorkflowTrace().executedAsPlanned()) {
            LOGGER.info("Workflow executed as planned.");
        } else {
            LOGGER.info("Workflow was not executed as planned.");
        }

        if (config.isResetWorkflowTracesBeforeSaving()) {
            state.getWorkflowTrace().reset();
        }
        try {
            if (getAfterExecutionCallback() != null) {
                getAfterExecutionCallback().apply(state);
            }
        } catch (Exception ex) {
            LOGGER.trace("Error during AfterExecutionCallback", ex);
        }
    }

    /**
     * Attempt to process any remaining bytes in the TCP receive buffer through the next
     * ReceivingAction. This is useful when send a stack of messages where the first already
     * triggers the other side to close with an alert. Otherwise, the IO Exception raised during
     * sending would cause us to abort the workflow trace without ever processing the alert.
     *
     * @param lastActionExecutedIndex The index of the last action executed (successful or not)
     */
    private void processPendingReceiveBufferBytes(int lastActionExecutedIndex) {
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        // execute next receiving action to ensure possibly remaining bytes of the TCP receive
        // buffer get parsed
        ReceivingAction nextReceiveAction = null;
        for (int i = lastActionExecutedIndex + 1; i < tlsActions.size(); i++) {
            if (tlsActions.get(i) instanceof ReceivingAction) {
                nextReceiveAction = (ReceivingAction) tlsActions.get(i);
                break;
            }
        }

        if (nextReceiveAction != null) {
            try {
                this.executeAction((TlsAction) nextReceiveAction, state);
            } catch (Exception ignored) {

            }
        }
    }
}
