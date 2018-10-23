/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.connectivity;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class ConnectivityChecker {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Connection connection;

    /**
     *
     * @param connection
     */
    public ConnectivityChecker(Connection connection) {
        this.connection = connection;
    }

    /**
     *
     * @return
     */
    public boolean isConnectable() {
        if (connection.getTransportHandlerType() == null) {
            connection.setTransportHandlerType(TransportHandlerType.TCP);
        }
        if (connection.getTimeout() == null) {
            connection.setTimeout(5000);
        }
        TransportHandler handler = TransportHandlerFactory.createTransportHandler(connection);
        try {
            handler.initialize();
        } catch (IOException ex) {
            LOGGER.debug(ex);
            return false;
        }
        if (handler.isInitialized()) {
            try {
                handler.closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
            return true;
        } else {
            return false;
        }
    }

    public boolean speaksTls(Config config) {
        config.setHttpsParsingEnabled(Boolean.TRUE);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        ReceiveTillAction receiveTillAction = new ReceiveTillAction(new ServerHelloDoneMessage());
        trace.addTlsAction(receiveTillAction);
        State state = new State(config, trace);
        WorkflowExecutor executor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state);
        executor.executeWorkflow();
        if (receiveTillAction.getRecords().size() > 0) {
            if (receiveTillAction.getRecords().get(0) instanceof Record) {
                return true;
            } else {
                for (ProtocolMessage message : receiveTillAction.getReceivedMessages()) {
                    if (message instanceof ServerHelloMessage || message instanceof ServerHelloDoneMessage
                            || message instanceof SSL2ServerHelloMessage) {
                        return true;
                    }
                }
                return false;
            }
        } else {
            return false;
        }
    }
}
