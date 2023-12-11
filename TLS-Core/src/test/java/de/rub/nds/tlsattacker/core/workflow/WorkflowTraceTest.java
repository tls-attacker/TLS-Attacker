/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.DummyReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.DummySendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.LinkedList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class WorkflowTraceTest {

    private WorkflowTrace trace;
    private Config config;
    private State state;
    private FakeTransportHandler fakeTransportHandler;

    @BeforeEach
    public void setUp() {
        config = new Config();
        trace = new WorkflowTrace();
        fakeTransportHandler = new FakeTransportHandler(null);
    }

    /** Test of makeGeneric method, of class WorkflowTrace. */
    @Test
    @Disabled("Not implemented")
    public void testMakeGeneric() {}

    /** Test of strip method, of class WorkflowTrace. */
    @Test
    @Disabled("Not implemented")
    public void testStrip() {}

    /** Test of reset method, of class WorkflowTrace. */
    @Test
    @Disabled("Not implemented")
    public void testReset() {}

    /** Test of getDescription method, of class WorkflowTrace. */
    @Test
    public void testGetDescription() {
        trace.setDescription("testDesc");
        assertEquals("testDesc", trace.getDescription());
    }

    /** Test of setDescription method, of class WorkflowTrace. */
    @Test
    public void testSetDescription() {
        trace.setDescription("testDesc");
        assertEquals("testDesc", trace.getDescription());
    }

    /** Test of add method, of class WorkflowTrace. */
    @Test
    public void testAdd_TLSAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        assertEquals(3, trace.getTlsActions().size());
        trace.addTlsAction(new ReceiveAction());
        assertEquals(new ReceiveAction(), trace.getTlsActions().get(3));
    }

    /** Test of add method, of class WorkflowTrace. */
    @Test
    public void testAdd_int_TLSAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        assertEquals(3, trace.getTlsActions().size());
        trace.addTlsAction(0, new ReceiveAction());
        assertEquals(new ReceiveAction(), trace.getTlsActions().get(0));
    }

    /** Test of remove method, of class WorkflowTrace. */
    @Test
    public void testRemove() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        assertEquals(3, trace.getTlsActions().size());
        trace.removeTlsAction(0);
        assertEquals(2, trace.getTlsActions().size());
    }

    /** Test of getTlsActions method, of class WorkflowTrace. */
    @Test
    public void testGetTLSActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        assertEquals(2, trace.getTlsActions().size());
        assertEquals(new SendAction(), trace.getTlsActions().get(0));
        assertEquals(new ReceiveAction(), trace.getTlsActions().get(1));
    }

    /** Test of setTlsActions method, of class WorkflowTrace. */
    @Test
    public void testSetTlsActions() {
        LinkedList<TlsAction> actionList = new LinkedList<>();
        actionList.add(new SendAction());
        actionList.add(new ReceiveAction());
        trace.setTlsActions(actionList);
        assertEquals(2, trace.getTlsActions().size());
        assertEquals(new SendAction(), trace.getTlsActions().get(0));
        assertEquals(new ReceiveAction(), trace.getTlsActions().get(1));
    }

    /** Test of getMessageActions method, of class WorkflowTrace. */
    @Test
    public void testGetMessageActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ChangeClientRandomAction());
        assertEquals(2, trace.getMessageActions().size());
        assertEquals(new SendAction(), trace.getMessageActions().get(0));
        assertEquals(new ReceiveAction(), trace.getMessageActions().get(1));
    }

    /** Test of getReceiveActions method, of class WorkflowTrace. */
    @Test
    public void testGetReceiveActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ChangeClientRandomAction());
        assertEquals(1, trace.getReceivingActions().size());
        assertEquals(new ReceiveAction(), trace.getReceivingActions().get(0));
    }

    /** Test of testGetSendingActions method, of class WorkflowTrace. */
    @Test
    public void testGetSendingActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ChangeClientRandomAction());
        assertEquals(1, trace.getSendingActions().size());
        assertEquals(new SendAction(), trace.getSendingActions().get(0));
    }

    /** Test of getLastAction method, of class WorkflowTrace. */
    @Test
    public void testGetLastAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ChangeCipherSuiteAction());
        assertEquals(new ChangeCipherSuiteAction(), trace.getLastAction());
    }

    /** Test of getLastMessageAction method, of class WorkflowTrace. */
    @Test
    public void testGetLastMessageAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ChangeCipherSuiteAction());
        assertEquals(new SendAction(), trace.getLastMessageAction());
        trace.addTlsAction(new ReceiveAction());
        assertEquals(new ReceiveAction(), trace.getLastMessageAction());
    }

    /** Test of configuredLooksLikeActual method, of class WorkflowTrace. */
    @Test
    @Disabled("Not implemented")
    public void testConfiguredLooksLikeActual() {}

    /** Test of getName method, of class WorkflowTrace. */
    @Test
    public void testGetName() {
        trace.setName("testName");
        assertEquals("testName", trace.getName());
    }

    /** Test of setName method, of class WorkflowTrace. */
    @Test
    public void testSetName() {
        trace.setName("testName");
        assertEquals("testName", trace.getName());
    }

    @Test
    public void testGetFirstReceivedMessage() {
        DummySendingAction sendClientHelloAction = new DummySendingAction(new ClientHelloMessage());
        DummySendingAction sendHeartbeatAction = new DummySendingAction(new HeartbeatMessage());
        AlertMessage alertMessage = new AlertMessage();
        ServerHelloMessage serverHelloMessage = new ServerHelloMessage();

        DummyReceivingAction receiveAlertMessageAction = new DummyReceivingAction(alertMessage);
        DummyReceivingAction receiveServerHelloAction =
                new DummyReceivingAction(serverHelloMessage);

        trace.addTlsActions(
                sendClientHelloAction,
                receiveAlertMessageAction,
                sendHeartbeatAction,
                receiveServerHelloAction);

        state = new State(config, trace);
        assertEquals(alertMessage, trace.getFirstReceivedMessage(AlertMessage.class));
        assertEquals(serverHelloMessage, trace.getLastReceivedMessage(ServerHelloMessage.class));
    }

    public void testGetFirstSentMessage() {
        ReceiveAction receiveAlertMessageAction = new ReceiveAction();
        receiveAlertMessageAction.setExpectedMessages(new AlertMessage());

        ReceiveAction receiveServerHelloAction = new ReceiveAction();
        receiveServerHelloAction.setExpectedMessages(new ServerHelloMessage());

        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        HeartbeatMessage heartbeat = new HeartbeatMessage();

        SendAction sendClientHelloAction = new SendAction(clientHello);
        SendAction sendHeartbeatAction = new SendAction(heartbeat);

        trace.addTlsActions(
                sendClientHelloAction,
                receiveAlertMessageAction,
                sendHeartbeatAction,
                receiveServerHelloAction);
        state = new State(config, trace);

        state.getTlsContext().setTransportHandler(fakeTransportHandler);
        state.getContext()
                .setLayerStack(
                        new LayerStack(
                                state.getContext(),
                                new MessageLayer(state.getTlsContext()),
                                new TcpLayer(state.getTcpContext())));
        sendClientHelloAction.execute(state);
        sendHeartbeatAction.execute(state);

        assertEquals(clientHello, trace.getFirstSentMessage(ClientHelloMessage.class));
        assertEquals(heartbeat, trace.getFirstSentMessage(HeartbeatMessage.class));
    }
}
