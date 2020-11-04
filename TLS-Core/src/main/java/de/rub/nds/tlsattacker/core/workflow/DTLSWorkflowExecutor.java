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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.File;
import java.io.IOException;
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

        int count = 0;
        boolean error = false;
        int errorAction = -1;
        for (int i = 0; i < tlsActions.size(); i++) {

            // Führe Action aus
            TlsAction action = tlsActions.get(i);
            try {
                action.execute(state);
            } catch (PreparationException | WorkflowExecutionException ex) {
                throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
            }
            // Nicht wie geplant abgelaufen
            // TODO: ReceiveAction macht hier Probleme, falls mehr Nachrichten
            // erhalten als erwartet... Eventuell ReceiveAction fixen.
            if (!action.executedAsPlanned()) {
                // Breche ab
                if (config.isStopTraceAfterUnexpected()) {
                    LOGGER.debug("Skipping all Actions, action did not execute as planned.");
                    break;
                }
                // Breche ab
                if ((state.getConfig().isStopActionsAfterFatal() && isReceivedFatalAlert())) {
                    LOGGER.debug("Skipping all Actions, received FatalAlert, StopActionsAfterFatal active");
                    break;
                }
                // Breche ab
                if ((state.getConfig().getStopActionsAfterIOException() && isIoException())) {
                    LOGGER.debug("Skipping all Actions, received IO Exception, StopActionsAfterIOException active");
                    break;
                }
                // Breche ab, da maximale Anzahl Retransmissions gemacht
                if (count == config.getMaxRetransmissions()) {
                    break;
                }
                // TODO: Setze nur aktuelle und vorherige Action zurück. Das
                // reicht nicht aus...
                action.reset();
                tlsActions.get(i - 1).reset();
                i = i - 2;
                count++;
                error = true;
                errorAction = i;
                // Wie geplant abgelaufen
            } else {
                if (errorAction == i && error) {
                    count = 0;
                    error = false;
                }
            }

        }

        // Close with Notify, if execution error
        TlsAction action = tlsActions.get(tlsActions.size() - 1);
        try {
            if (error && config.isFinishWithCloseNotify()) {
                action.execute(state);
            }
        } catch (PreparationException | WorkflowExecutionException ex) {
            throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
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
