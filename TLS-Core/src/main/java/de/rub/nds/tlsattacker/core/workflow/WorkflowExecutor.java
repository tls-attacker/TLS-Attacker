/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.BouncyCastleNotLoadedException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    static {
        if (!BouncyCastleProviderChecker.isLoaded()) {
            throw new BouncyCastleNotLoadedException("BouncyCastleProvider not loaded");
        }
    }

    protected final WorkflowExecutorType type;

    protected final State state;
    protected final Config config;

    /**
     * Prepare a workflow trace for execution according to the given state and executor type. Try various ways to
     * initialize a workflow trace and add it to the state. For workflow creation, use the first method which does not
     * return null, in the following order: state.getWorkflowTrace(), state.config.getWorkflowInput(),
     * config.getWorkflowTraceType().
     * 
     * @param type
     *              of the workflow executor (currently only DEFAULT)
     * @param state
     *              to work on
     */
    public WorkflowExecutor(WorkflowExecutorType type, State state) {
        this.type = type;
        this.state = state;
        this.config = state.getConfig();
    }

    public abstract void executeWorkflow() throws WorkflowExecutionException;

    public void initTranstHandler() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            AliasedConnection con = ctx.getConnection();
            if (con.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
                LOGGER.info("Waiting for incoming connection on " + con.getHostname() + ":" + con.getPort());
            } else {
                LOGGER.info("Connecting to " + con.getHostname() + ":" + con.getPort());
            }
            ctx.initTransportHandler();
            LOGGER.debug("Connection for " + ctx + " initialized");
        }
    }

    public void closeConnection() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            try {
                ctx.getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.warn("Could not close connection for context " + ctx);
                LOGGER.debug(ex);
            }
        }
    }

    public void initRecordLayer() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            ctx.initRecordLayer();
        }
    }

    public void setFinalSocketState() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            TransportHandler handler = ctx.getTransportHandler();
            if (handler instanceof TcpTransportHandler) {
                SocketState socketSt =
                    ((TcpTransportHandler) handler).getSocketState(config.isReceiveFinalTcpSocketStateWithTimeout());
                ctx.setFinalSocketState(socketSt);
            } else {
                ctx.setFinalSocketState(SocketState.UNAVAILABLE);
            }
        }
    }

    /**
     * Check if a at least one TLS context received a fatal alert.
     */
    public boolean isReceivedFatalAlert() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            if (ctx.isReceivedFatalAlert()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a at least one TLS context received a warning alert.
     */
    public boolean isReceivedWarningAlert() {
        List<ProtocolMessage> allReceivedMessages =
            WorkflowTraceUtil.getAllReceivedMessages(state.getWorkflowTrace(), ProtocolMessageType.ALERT);
        for (ProtocolMessage message : allReceivedMessages) {
            AlertMessage alert = (AlertMessage) message;
            if (alert.getLevel().getValue() == AlertLevel.WARNING.getValue()) {
                return true;
            }
        }
        return false;
    }

    public boolean isIoException() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            if (ctx.isReceivedTransportHandlerException()) {
                return true;
            }
        }
        return false;
    }
}
