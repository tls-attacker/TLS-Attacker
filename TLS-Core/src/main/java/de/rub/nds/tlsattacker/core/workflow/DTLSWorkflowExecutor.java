/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.biginteger.BigIntegerExplicitValueModification;
import de.rub.nds.tlsattacker.core.config.ConfigIO;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.LinkedList;
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
            if (i != 0 && !(tlsActions.get(i) instanceof ReceivingAction)
                && (tlsActions.get(i - 1) instanceof ReceivingAction)) {
                retransmissionActionIndex = i;
            }
            TlsAction action = tlsActions.get(i);
            if (!action.isExecuted()) {
                try {
                    action.execute(state);
                } catch (UnsupportedOperationException E) {
                    LOGGER.warn("Unsupported operation!", E);
                    state.setExecutionException(E);
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
                        executeRetransmission((SendingAction) action);
                    } else if (action instanceof ReceivingAction) {
                        action.reset();
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
                } else if (retransmissions == config.getMaxDtlsRetransmissions()) {
                    break;
                } else {
                    i = retransmissionActionIndex - 1;
                    retransmissions++;
                }
            }
        }

        if (config.isFinishWithCloseNotify()) {
            int dtlsWriteEpoch = state.getTlsContext().getWriteEpoch();
            for (int epoch = dtlsWriteEpoch; epoch >= 0; epoch--) {
                state.getTlsContext().setWriteEpoch(epoch);
                sendCloseNotify();
            }
            state.getTlsContext().setWriteEpoch(dtlsWriteEpoch);
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

    private void executeRetransmission(SendingAction action) throws IOException {
        LOGGER.info("Executing retransmission of last sent flight");
        for (AbstractRecord abstractRecord : action.getSendRecords()) {
            if (abstractRecord instanceof Record) {
                Record record = (Record) abstractRecord;
                record.setSequenceNumber(
                    BigInteger.valueOf(state.getTlsContext().getWriteSequenceNumber(record.getEpoch().getValue())));
                List<AbstractRecord> records = new LinkedList<>();
                records.add(record);
                state.getTlsContext().getRecordLayer().prepareRecords(record.getCleanProtocolMessageBytes().getValue(),
                    record.getContentMessageType(), records, false);
                state.getTlsContext().increaseWriteSequenceNumber(record.getEpoch().getValue());
            }
        }
        sendMessageHelper.sendRecords(action.getSendRecords(), state.getTlsContext());
    }

}
