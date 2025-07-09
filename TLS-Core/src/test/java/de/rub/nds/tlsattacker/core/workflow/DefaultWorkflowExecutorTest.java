/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class DefaultWorkflowExecutorTest {

    /** Fallback to WorkflowConfigurationFactory with default context should work. */
    @Test
    public void testExecuteImplicitWorkflowWithDefaultContexts() {
        Config config = new Config();
        config.setWorkflowTraceType(WorkflowTraceType.HELLO);
        State state = new State(config);
        assertDoesNotThrow(() -> new DefaultWorkflowExecutor(state));
    }

    @Test
    public void testIOExceptionInSendActionProcessesPendingAlert() throws ConfigurationException {
        Config config = new Config();
        config.setStopActionsAfterIOException(true);

        FakeTcpTransportHandler transportHandler =
                new FakeTcpTransportHandler(ConnectionEndType.CLIENT);

        // We set an alert but expect a ServerHello to ensure handling of unexpected alerts works
        byte[] alertRecord = new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
        transportHandler.setFetchableByte(alertRecord);

        WorkflowTrace trace = new WorkflowTrace();

        SendAction sendAction = new SendAction();
        ClientHelloMessage clientHello = new ClientHelloMessage();
        sendAction.setConfiguredMessages(clientHello);

        ReceiveAction receiveAction = new ReceiveAction();
        ServerHelloMessage serverHello = new ServerHelloMessage();
        receiveAction.setExpectedMessages(serverHello);

        trace.addTlsAction(sendAction);
        trace.addTlsAction(receiveAction);

        State state = new State(config, trace);
        TlsContext context = state.getTlsContext();
        context.setTransportHandler(transportHandler);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);

        // Configure transport handler to throw IOException on send
        transportHandler.setThrowExceptionOnSend(true);

        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();

        assertNotNull(receiveAction.getReceivedMessages());
        assertEquals(1, receiveAction.getReceivedMessages().size());
        assertTrue(receiveAction.getReceivedMessages().get(0) instanceof AlertMessage);

        AlertMessage receivedAlert = (AlertMessage) receiveAction.getReceivedMessages().get(0);
        assertEquals(AlertLevel.FATAL.getValue(), receivedAlert.getLevel().getValue().byteValue());
        assertEquals(
                AlertDescription.HANDSHAKE_FAILURE.getValue(),
                receivedAlert.getDescription().getValue().byteValue());

        assertFalse(sendAction.executedAsPlanned());
        assertTrue(receiveAction.isExecuted());
    }
}
