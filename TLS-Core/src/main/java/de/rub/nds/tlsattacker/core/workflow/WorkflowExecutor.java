/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.BouncyCastleNotLoadedException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.TransportHandlerConnectException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerFactory;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import java.io.IOException;
import java.util.List;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    private Function<State, Integer> beforeTransportPreInitCallback = null;

    private Function<State, Integer> beforeTransportInitCallback = null;

    private Function<State, Integer> afterTransportInitCallback = null;

    private Function<State, Integer> afterExecutionCallback = null;

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

    /**
     * Initialize the context's transport handler.Start listening or connect to a server, depending on our connection
     * end type.
     *
     * @param context
     */
    public void initTransportHandler(TlsContext context) {

        if (context.getTransportHandler() == null) {
            if (context.getConnection() == null) {
                throw new ConfigurationException("Connection end not set");
            }
            context.setTransportHandler(TransportHandlerFactory.createTransportHandler(context.getConnection()));
            if (context.getTransportHandler() instanceof ClientTcpTransportHandler) {
                ((ClientTcpTransportHandler) context.getTransportHandler())
                    .setRetryFailedSocketInitialization(config.isRetryFailedClientTcpSocketInitialization());
            }
        }

        try {
            if (getBeforeTransportPreInitCallback() != null) {
                getBeforeTransportPreInitCallback().apply(state);
            }
            context.getTransportHandler().preInitialize();
            if (getBeforeTransportInitCallback() != null) {
                getBeforeTransportInitCallback().apply(state);
            }
            context.getTransportHandler().initialize();
            if (getAfterTransportInitCallback() != null) {
                getAfterTransportInitCallback().apply(state);
            }
        } catch (NullPointerException | NumberFormatException ex) {
            throw new ConfigurationException("Invalid values in " + context.getConnection().toString(), ex);
        } catch (Exception ex) {
            throw new TransportHandlerConnectException(
                "Unable to initialize the transport handler with: " + context.getConnection().toString(), ex);
        }
    }

    /**
     * Initialize the context's record layer.
     *
     * @param context
     */
    public void initRecordLayer(TlsContext context) {
        if (context.getRecordLayerType() == null) {
            throw new ConfigurationException("No record layer type defined");
        }
        context.setRecordLayer(RecordLayerFactory.getRecordLayer(context.getRecordLayerType(), context));
    }

    public Function<State, Integer> getBeforeTransportPreInitCallback() {
        return beforeTransportPreInitCallback;
    }

    public void setBeforeTransportPreInitCallback(Function<State, Integer> beforeTransportPreInitCallback) {
        this.beforeTransportPreInitCallback = beforeTransportPreInitCallback;
    }

    public Function<State, Integer> getBeforeTransportInitCallback() {
        return beforeTransportInitCallback;
    }

    public void setBeforeTransportInitCallback(Function<State, Integer> beforeTransportInitCallback) {
        this.beforeTransportInitCallback = beforeTransportInitCallback;
    }

    public Function<State, Integer> getAfterTransportInitCallback() {
        return afterTransportInitCallback;
    }

    public void setAfterTransportInitCallback(Function<State, Integer> afterTransportInitCallback) {
        this.afterTransportInitCallback = afterTransportInitCallback;
    }

    public Function<State, Integer> getAfterExecutionCallback() {
        return afterExecutionCallback;
    }

    public void setAfterExecutionCallback(Function<State, Integer> afterExecutionCallback) {
        this.afterExecutionCallback = afterExecutionCallback;
    }

    public void initAllTransportHandler() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            AliasedConnection con = ctx.getConnection();
            if (con.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
                LOGGER.info("Waiting for incoming connection on " + con.getHostname() + ":" + con.getPort());
            } else {
                LOGGER.info("Connecting to " + con.getHostname() + ":" + con.getPort());
            }
            initTransportHandler(ctx);
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

    public void initAllRecordLayer() {
        for (TlsContext ctx : state.getAllTlsContexts()) {
            initRecordLayer(ctx);
        }
    }

    public void sendCloseNotify() {
        AlertMessage alertMessage = new AlertMessage();
        alertMessage.setConfig(AlertLevel.FATAL, AlertDescription.CLOSE_NOTIFY);
        SendAction sendAction =
            new SendAction(state.getWorkflowTrace().getConnections().get(0).getAlias(), alertMessage);
        sendAction.getActionOptions().add(ActionOption.MAY_FAIL);
        sendAction.execute(state);
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
