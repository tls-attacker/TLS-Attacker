/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.ConfigIO;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
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
        if (config.isWorkflowExecutorShouldOpen()) {
            initTranstHandler();
        }
        initRecordLayer();

        state.getWorkflowTrace().reset();
        state.setStartTimestamp(System.currentTimeMillis());
        int numTlsContexts = state.getAllTlsContexts().size();
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        int retransmissions = 0;
        for (int i = 0; i < tlsActions.size(); i++) {
            // TODO: in multi ctx scenarios, how to handle earlyCleanShutdown ?
            if (numTlsContexts == 1 && state.getTlsContext().isEarlyCleanShutdown()) {
                LOGGER.debug("Clean shutdown of execution flow");
                break;
            }

            TlsAction action = tlsActions.get(i);
            if (!action.isExecuted()) {
                try {
                    action.execute(state);
                } catch (PreparationException | WorkflowExecutionException ex) {
                    state.setExecutionException(ex);
                    throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
                } catch (Exception e) {
                    LOGGER.error("", e);
                    state.setExecutionException(e);
                    throw e;
                } finally {
                    state.setEndTimestamp(System.currentTimeMillis());
                }
            } else {
                try {
                    if (action instanceof SendingAction) {

                        SendMessageHelper sendMessageHelper = new SendMessageHelper();
                        for (AbstractRecord record : ((SendingAction) action).getSendRecords()) {
                            ((Record) record)
                                .setSequenceNumber(BigInteger.valueOf(state.getTlsContext().getWriteSequenceNumber()));
                            state.getTlsContext().increaseWriteSequenceNumber();
                        }
                        sendMessageHelper.sendRecords(((SendingAction) action).getSendRecords(), state.getTlsContext());

                    } else if (action instanceof ReceivingAction) {

                        action.execute(state);

                    }
                } catch (IOException | PreparationException | WorkflowExecutionException ex) {
                    throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
                }
            }

            if ((config.isStopActionsAfterFatal() && isReceivedFatalAlert())) {
                LOGGER.debug("Skipping all Actions, received FatalAlert, StopActionsAfterFatal active");
                break;
            }
            if ((config.getStopActionsAfterWarning() && isReceivedWarningAlert())) {
                LOGGER.debug("Skipping all Actions, received Warning Alert, StopActionsAfterWarning active");
                break;
            }
            if ((config.getStopActionsAfterIOException() && isIoException())) {
                LOGGER.debug("Skipping all Actions, received IO Exception, StopActionsAfterIOException active");
                break;
            }

            if (!action.executedAsPlanned()) {
                if (config.isStopTraceAfterUnexpected()) {
                    LOGGER.debug("Skipping all Actions, action did not execute as planned.");
                    break;
                } else if (retransmissions == config.getMaxRetransmissions()) {
                    break;
                } else {
                    int j = i;
                    for (; j >= 0; j--) {
                        if (tlsActions.get(j) instanceof ReceivingAction) {
                            tlsActions.get(j).reset();
                        } else {
                            break;
                        }

                    }
                    for (; j >= 0; j--) {
                        if (tlsActions.get(j) instanceof ReceivingAction) {
                            break;
                        }

                    }
                    i = j;
                    retransmissions++;
                }
            }
        }

        if (config.isFinishWithCloseNotify()) {
            int dtlsWriteEpoch = state.getTlsContext().getDtlsWriteEpoch();
            for (int epoch = dtlsWriteEpoch; epoch >= 0; epoch--) {
                state.getTlsContext().setDtlsWriteEpoch(epoch);
                sendCloseNotify();
            }
            state.getTlsContext().setDtlsWriteEpoch(dtlsWriteEpoch);
        }

        setFinalSocketState();

        if (config.isWorkflowExecutorShouldClose()) {
            closeConnection();
        }
        if (config.isResetWorkflowTracesBeforeSaving()) {
            state.getWorkflowTrace().reset();
        }

        state.storeTrace();

        if (config.getConfigOutput() != null) {
            ConfigIO.write(config, new File(config.getConfigOutput()));
        }
    }

}
