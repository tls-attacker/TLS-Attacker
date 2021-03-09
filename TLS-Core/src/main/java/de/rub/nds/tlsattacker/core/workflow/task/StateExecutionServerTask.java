/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.task;

import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Callable;

/**
 * Do not use this Task if you want to rely on the socket state
 */
public class StateExecutionServerTask extends TlsTask {
    private static final Logger LOGGER = LogManager.getLogger();
    private final State state;
    private final ServerSocket serverSocket;
    private Callable<Integer> beforeAcceptCallback = () -> {
        return 0;
    };
    private boolean stateFinished = false;

    public StateExecutionServerTask(State state, ServerSocket serverSocket, int reexecutions) {
        super(reexecutions);
        this.state = state;
        this.serverSocket = serverSocket;
    }

    private Socket acceptConnection() throws IOException {
        try {
            new Thread(() -> {
                boolean success = false;
                while (!success && !stateFinished) {
                    try {
                        Thread.sleep(10);
                        int retVal = beforeAcceptCallback.call();
                        success = retVal == 0;
                    } catch (Exception e) {
                        LOGGER.error(e);
                        try {
                            Thread.sleep(200);
                        } catch (InterruptedException ignored) {
                        }
                    }
                }
            }).start();

            return serverSocket.accept();
        } catch (IOException e) {
            LOGGER.error(e);
            throw e;
        }
    }

    @Override
    public boolean execute() {
        stateFinished = false;
        try {
            return innerExecute();
        } catch (Exception e) {
            stateFinished = true;
            throw e;
        }
    }

    private boolean innerExecute() {
        Socket socket;
        try {
            socket = acceptConnection();
        } catch (IOException E) {
            throw new RuntimeException("error accepting the connection", E);
        }

        // Do this post state init only if you know what you are doing.
        TlsContext serverCtx = state.getInboundTlsContexts().get(0);
        AliasedConnection serverCon = serverCtx.getConnection();
        serverCon.setHostname(socket.getInetAddress().getHostAddress());
        serverCon.setPort(socket.getLocalPort());
        if (serverCon.getFirstTimeout() == null)
            serverCon.setFirstTimeout(serverCon.getTimeout());

        ServerTcpTransportHandler th;
        try {
            th = new ServerTcpTransportHandler(serverCon, socket);
        } catch (IOException ex) {
            LOGGER.error("Could not prepare TransportHandler for " + socket);
            LOGGER.error("Aborting workflow trace execution on " + socket);
            return false;
        }
        serverCtx.setTransportHandler(th);

        LOGGER.info("Exectuting workflow for " + socket + " (" + serverCtx + ")");
        DefaultWorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);

        try {
            workflowExecutor.executeWorkflow();
        } catch (Exception e) {
            throw e;
        }

        if (state.getTlsContext().isReceivedTransportHandlerException()) {
            throw new RuntimeException("TransportHandler exception received.");
        }

        LOGGER.info("Workflow execution done on " + socket + " (" + serverCtx + ")");
        return true;
    }

    public State getState() {
        return state;
    }

    @Override
    public void reset() {
        state.reset();
    }

    public Callable<Integer> getBeforeAcceptCallback() {
        return beforeAcceptCallback;
    }

    public void setBeforeAcceptCallback(Callable<Integer> beforeAcceptCallback) {
        this.beforeAcceptCallback = beforeAcceptCallback;
    }
}
