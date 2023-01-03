/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.SkipActionException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.protocol.message.ack.RecordNumber;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.IOException;
import java.math.BigInteger;
import java.util.LinkedList;
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
        int retransmissionActionIndex = 0;
        for (int i = 0; i < tlsActions.size(); i++) {
            if (i != 0
                    && !(tlsActions.get(i) instanceof ReceivingAction)
                    && (tlsActions.get(i - 1) instanceof ReceivingAction)) {
                retransmissionActionIndex = i;
            }
            TlsAction action = tlsActions.get(i);

            if (!action.isExecuted()) {
                try {
                    this.executeAction(action, state);
                } catch (SkipActionException ex) {
                    continue;
                }
            } else {
                if (action instanceof SendingAction) {
                    executeRetransmission((SendingAction) action);
                } else if (action instanceof ReceivingAction) {
                    action.reset();
                    try {
                        this.executeAction(action, state);
                    } catch (SkipActionException ex) {
                        continue;
                    }
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
                    break;
                } else {
                    i = retransmissionActionIndex - 1;
                    retransmissions++;
                }
            } else {
                if (action instanceof ReceivingAction
                        && state.getTlsContext().getChooser().getSelectedProtocolVersion()
                                == ProtocolVersion.DTLS13) {
                    LOGGER.debug("Clearing received ACKs");
                    if (state.getTlsContext().getReceivedAcknowledgedRecords() != null) {
                        state.getTlsContext().getReceivedAcknowledgedRecords().clear();
                    }
                }
            }
        }

        if (config.isFinishWithCloseNotify()) {
            int currentEpoch = state.getTlsContext().getRecordLayer().getWriteEpoch();
            for (int epoch = currentEpoch; epoch >= 0; epoch--) {
                state.getTlsContext().getRecordLayer().setWriteEpoch(epoch);
                if (state.getTlsContext().getRecordLayer().getEncryptor().getRecordCipher(epoch)
                        == null) {
                    LOGGER.debug(
                            "Not sending a close notify for epoch "
                                    + epoch
                                    + ". No cipher available.");
                    continue;
                }
                sendCloseNotify();
            }
            state.getTlsContext().getRecordLayer().setWriteEpoch(currentEpoch);
        }

        setFinalSocketState();

        closeConnection();
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

    private void executeRetransmission(SendingAction action) {
        LOGGER.info("Executing retransmission of last sent flight");
        List<Record> recordsToRetransmit = filterRecordsBasedOnAcks(action.getSendRecords());
        state.getTlsContext()
                .getRecordLayer()
                .setLayerConfiguration(
                        new SpecificSendLayerConfiguration(
                                ImplementedLayers.RECORD, recordsToRetransmit));
        try {
            state.getTlsContext().getRecordLayer().sendConfiguration();
        } catch (IOException ex) {
            state.getTlsContext().setReceivedTransportHandlerException(true);
        }
    }

    private List<Record> filterRecordsBasedOnAcks(List<Record> sendRecords) {
        List<RecordNumber> acks = state.getTlsContext().getAcknowledgedRecords();
        if (acks == null || acks.isEmpty()) {
            return sendRecords;
        }
        List<Record> filteredRecords = new LinkedList<>();
        for (Record record : sendRecords) {
            if (!isRecordAcknowledged(record, acks)) {
                filteredRecords.add(record);
            }
        }
        return filteredRecords;
    }

    private boolean isRecordAcknowledged(Record record, List<RecordNumber> acknowledgedRecords) {
        for (RecordNumber ack : acknowledgedRecords) {
            BigInteger epoch = ack.getEpoch().getValue();
            BigInteger seqNum = ack.getSequenceNumber().getValue();
            if (record.getEpoch().getValue().equals(epoch.intValue())
                    && record.getSequenceNumber().getValue().equals(seqNum)) {
                return true;
            }
        }
        return false;
    }
}
