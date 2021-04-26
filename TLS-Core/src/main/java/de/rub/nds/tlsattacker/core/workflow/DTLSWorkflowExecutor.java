/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.ConfigIO;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.DtlsCloseConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DTLSWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    public DTLSWorkflowExecutor(State state) {
        super(WorkflowExecutorType.DTLS, state);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        List<TlsContext> allTlsContexts = state.getAllTlsContexts();

        if (config.isWorkflowExecutorShouldOpen()) {
            for (TlsContext ctx : allTlsContexts) {
                AliasedConnection con = ctx.getConnection();
                if (con.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
                    LOGGER.info("Waiting for incoming connection on " + con.getHostname() + ":" + con.getPort());
                } else {
                    LOGGER.info("Connecting to " + con.getHostname() + ":" + con.getPort());
                }
                ctx.initTransportHandler();
                LOGGER.debug("Connection for " + ctx + " initiliazed");
            }
        }

        for (TlsContext ctx : state.getAllTlsContexts()) {
            ctx.initRecordLayer();
        }

        state.getWorkflowTrace().reset();
        int numTlsContexts = allTlsContexts.size();
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();

        // ------------------------------------------

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
                    throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
                }
            } else {
                try {
                    if (action instanceof SendingAction) {

                        SendMessageHelper sendMessageHelper = new SendMessageHelper();
                        for (AbstractRecord record : ((SendingAction) action).getSendRecords()) {
                            ((Record) record).setSequenceNumber(((Record) record).getSequenceNumber().getValue()
                                    .add(BigInteger.ONE));
                        }
                        sendMessageHelper.sendRecords(((SendingAction) action).getSendRecords(), state.getTlsContext());

                    } else if (action instanceof ReceivingAction) {

                        action.execute(state);

                    }
                } catch (IOException | PreparationException | WorkflowExecutionException ex) {
                    throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
                }
            }

            if ((state.getConfig().isStopActionsAfterFatal() && isReceivedFatalAlert())) {
                LOGGER.debug("Skipping all Actions, received FatalAlert, StopActionsAfterFatal active");
                break;
            }
            if ((state.getConfig().getStopActionsAfterIOException() && isIoException())) {
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
                            i = j;
                            break;
                        }

                    }
                    retransmissions++;
                }
            }
        }

        // Close Notify mit allen Epochs
        if (config.isFinishWithCloseNotify() && config.getHighestProtocolVersion().isDTLS()) {
            for (int epoch = state.getTlsContext().getDtlsWriteEpoch(); epoch >= 0; epoch--) {
                DtlsCloseConnectionAction closeConnectionAction = new DtlsCloseConnectionAction(state
                        .getWorkflowTrace().getConnections().get(0).getAlias(), epoch);
                closeConnectionAction.getActionOptions().add(ActionOption.MAY_FAIL);
                closeConnectionAction.execute(state);
            }
        }
        // ------------------------------------------

        if (state.getConfig().isWorkflowExecutorShouldClose()) {
            for (TlsContext ctx : state.getAllTlsContexts()) {
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

        state.storeTrace();

        if (config.getConfigOutput() != null) {
            ConfigIO.write(config, new File(config.getConfigOutput()));
        }
    }

    /**
     * Check if a at least one TLS context received a fatal alert.
     */
    private boolean isReceivedFatalAlert() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            if (ctx.isReceivedFatalAlert()) {
                return true;
            }
        }
        return false;
    }

    private boolean isIoException() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            if (ctx.isReceivedTransportHandlerException()) {
                return true;
            }
        }
        return false;
    }
}
