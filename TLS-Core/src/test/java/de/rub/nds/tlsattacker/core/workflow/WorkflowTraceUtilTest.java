/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *

 */
public class WorkflowTraceUtilTest {

    private WorkflowTrace trace;
    private Config config;

    private ReceiveAction rcvHeartbeat;
    private ReceiveAction rcvAlertMessage;
    private ReceiveAction rcvServerHello;
    private ReceiveAction rcvFinishedMessage;

    private SendAction sHeartbeat;
    private SendAction sAlertMessage;
    private SendAction sClientHello;
    private SendAction sFinishedMessage;

    public WorkflowTraceUtilTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        config = config.createConfig();
        trace = new WorkflowTrace(config);

        rcvHeartbeat = new ReceiveAction();
        rcvAlertMessage = new ReceiveAction();
        rcvServerHello = new ReceiveAction();
        rcvFinishedMessage = new ReceiveAction();

        rcvHeartbeat.setMessages(new HeartbeatMessage());
        rcvAlertMessage.setMessages(new AlertMessage());
        rcvServerHello.setMessages(new ServerHelloMessage());
        rcvFinishedMessage.setMessages(new FinishedMessage());

        sHeartbeat = new SendAction();
        sAlertMessage = new SendAction();
        sClientHello = new SendAction();
        sFinishedMessage = new SendAction();

        sHeartbeat.setMessages(new HeartbeatMessage());
        sAlertMessage.setMessages(new AlertMessage());
        sClientHello.setMessages(new ClientHelloMessage());
        sFinishedMessage.setMessages(new FinishedMessage());
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testDidReceiveMessage() {
        assertFalse(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertFalse(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        assertFalse(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(rcvHeartbeat);

        assertTrue(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertFalse(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        assertFalse(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(rcvAlertMessage);

        assertTrue(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        assertFalse(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(rcvServerHello);

        assertTrue(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertTrue(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        assertFalse(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(rcvFinishedMessage);

        assertTrue(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertTrue(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        assertTrue(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));
    }

    @Test
    public void testDidSendMessage() {
        assertFalse(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertFalse(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertFalse(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(sHeartbeat);

        assertTrue(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertFalse(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertFalse(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(sAlertMessage);

        assertTrue(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertFalse(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(sClientHello);

        assertTrue(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertTrue(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertFalse(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(sFinishedMessage);

        assertTrue(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertTrue(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertTrue(WorkflowTraceUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));
    }

}
