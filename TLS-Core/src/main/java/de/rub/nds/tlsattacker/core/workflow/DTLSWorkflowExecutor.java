/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DTLSWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    private SendMessageHelper sendMessageHelper;

    public DTLSWorkflowExecutor(State state) {
        super(WorkflowExecutorType.DTLS, state);
        sendMessageHelper = new SendMessageHelper();
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        if (config.isWorkflowExecutorShouldOpen()) {
            initAllTransportHandler();
        }
        initAllRecordLayer();

        state.getWorkflowTrace().reset();
        state.setStartTimestamp(System.currentTimeMillis());
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        int retransmissions = 0;
        int retransmissionActionIndex = 0;
        for (int i = 0; i < tlsActions.size(); i++) {
            if (i != 0
                    && !(tlsActions.get(i) instanceof ReceivingAction)
                    && (tlsActions.get(i - 1) instanceof ReceivingAction)) {
                retransmissionActionIndex = i;
            }
            TlsAction action = tlsActions.get(i);
            if (!action.isExecuted()) {
                LOGGER.trace("Executing regular action {} at index {}", action, i);
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
            } else {
                LOGGER.trace("Executing retransmission action {} at index {}", action, i);
                try {
                    if (action instanceof SendingAction) {
                        executeRetransmission((SendingAction) action);
                    } else if (action instanceof ReceivingAction) {
                        action.reset();
                        action.execute(state);
                    }
                } catch (IOException | PreparationException | WorkflowExecutionException ex) {
                    LOGGER.debug("Encoundered exception during retransmission", ex);
                    if (config.isWorkflowExecutorShouldClose()) {
                        closeConnection();
                    }
                    throw new WorkflowExecutionException(
                            "Problem while executing Action:" + action.toString(), ex);
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
                } else if (retransmissions == config.getMaxDtlsRetransmissions()) {
                    LOGGER.debug("Hit max retransmissions, stopping workflow");
                    break;
                } else {
                    LOGGER.trace(
                            "Stepping back index to perform retransmission. Was: {} will be {}",
                            i,
                            retransmissionActionIndex - 1);
                    i = retransmissionActionIndex - 1;
                    retransmissions++;
                }
            }
        }

        if (config.isFinishWithCloseNotify()) {
            LOGGER.info("Closing connections with close notify");
            for (TlsContext context : state.getAllTlsContexts()) {
                int currentEpoch = context.getRecordLayer().getWriteEpoch();
                for (int epoch = currentEpoch; epoch >= 0; epoch--) {
                    context.getRecordLayer().setWriteEpoch(epoch);
                    sendCloseNotify(context);
                }
                context.getRecordLayer().setWriteEpoch(currentEpoch);
            }
        }

        setFinalSocketState();

        if (config.isWorkflowExecutorShouldClose()) {
            LOGGER.debug("Closing connection");
            closeConnection();
        }
        if (config.isResetWorkflowTracesBeforeSaving()) {
            LOGGER.debug("Resetting WorkflowTrace");
            state.getWorkflowTrace().reset();
        }

        if (getAfterExecutionCallback() != null) {
            LOGGER.debug("Executing AfterExecutionCallback");
            for (TlsContext context : state.getAllTlsContexts()) {
                try {
                    getAfterExecutionCallback().apply(context);
                } catch (Exception ex) {
                    LOGGER.trace("Error during AfterExecutionCallback", ex);
                }
            }
        }
    }

    private void executeRetransmission(SendingAction action) throws IOException {
        LOGGER.info("Executing retransmission of last sent flight");
        for (String alias : action.getAllSendingAliases()) {
            LOGGER.debug("Retransmitting records for alias {}", alias);
            state.getTlsContext(alias).getRecordLayer().reencrypt(action.getSendRecords());
            sendMessageHelper.sendRecords(action.getSendRecords(), state.getTlsContext(alias));
        }
    }
}
