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
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DTLSWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    public DTLSWorkflowExecutor(State state) {
        super(WorkflowExecutorType.DTLS, state);
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
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        int retransmissions = 0;
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

            if (!action.executedAsPlanned() && action instanceof ReceivingAction) {
                if (config.isStopTraceAfterUnexpected()) {
                    LOGGER.debug("Skipping all Actions, action did not execute as planned.");
                    break;
                } else if (retransmissions == config.getMaxDtlsRetransmissions()) {
                    LOGGER.debug("Hit max retransmissions, stopping workflow");
                    break;
                } else {
                    LOGGER.trace(
                            "Stepping back index to perform retransmission. From index: {}", index);
                    try {
                        performRetransmissions(tlsActions, index);
                    } catch (IOException E) {
                        LOGGER.warn(
                                "IOException occured during retransmission. Stopping workflow.", E);
                        break;
                    }
                    action.reset();
                    retransmissions++;
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

        closeConnection();
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

    private void performRetransmissions(List<TlsAction> tlsActions, int receiveActionIndex)
            throws IOException {
        if (!(tlsActions.get(receiveActionIndex) instanceof ReceivingAction)) {
            throw new WorkflowExecutionException(
                    "Passed index of non receiving action as index. Index: "
                            + receiveActionIndex
                            + ", Type: "
                            + tlsActions.get(receiveActionIndex).getClass().getSimpleName());
        }
        ReceivingAction receivingAction = (ReceivingAction) tlsActions.get(receiveActionIndex);
        Set<String> receivingAliases = receivingAction.getAllReceivingAliases();
        // We will perform retransmissions for all receiving aliases, even if a subset
        // of those aliases actually does not need to have them
        int retransmissionIndex = findRetransmissionIndex(tlsActions, receiveActionIndex);
        for (int i = retransmissionIndex; i < receiveActionIndex; i++) {
            TlsAction action = tlsActions.get(i);
            if (action instanceof SendingAction) {
                SendingAction sendingAction = (SendingAction) action;
                if (sendingAction.getAllSendingAliases() != null
                        && !Collections.disjoint(
                                receivingAliases, sendingAction.getAllSendingAliases())) {
                    LOGGER.debug("Performing retransmission for action {}", sendingAction);
                    executeRetransmission(sendingAction);
                }
            }
        }
    }

    /**
     * We need to set the index to the correct value. We have to reexecute all sending actions in
     * the same context after the last receiving action.
     *
     * @param tlsActions The action in the workflow trace
     * @param index The index of the currently failing receiving action
     * @return the new index to start retransmissions from
     */
    private int findRetransmissionIndex(List<TlsAction> tlsActions, int index) {
        if (!(tlsActions.get(index) instanceof ReceivingAction)) {
            throw new WorkflowExecutionException("Passed index of non receiving action as index");
        }
        ReceivingAction receivingAction = (ReceivingAction) tlsActions.get(index);

        Set<String> aliases = receivingAction.getAllReceivingAliases();
        for (int i = index; i >= 0; i--) {
            TlsAction action = tlsActions.get(i);
            if (action instanceof ReceivingAction) {
                for (String alias : action.getAllAliases()) {
                    if (aliases.contains(alias)) {
                        return i + 1;
                    }
                }
                return i + 1;
            }
        }
        return 0; // We need to restart from the beginning
    }

    private void executeRetransmission(SendingAction action) throws IOException {
        LOGGER.info("Executing retransmission of last sent flight");
        for (String alias : action.getAllSendingAliases()) {
            LOGGER.debug("Retransmitting records for alias {}", alias);
            state.getTlsContext()
                    .getRecordLayer()
                    .setLayerConfiguration(
                            new SpecificSendLayerConfiguration(
                                    ImplementedLayers.RECORD, action.getSendRecords()));
            try {
                state.getTlsContext().getRecordLayer().sendConfiguration();
            } catch (IOException ex) {
                state.getTlsContext().setReceivedTransportHandlerException(true);
                LOGGER.warn("Received IOException during retransmission", ex);
            }
        }
    }
}
