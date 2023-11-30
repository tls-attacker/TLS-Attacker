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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class WorkflowTraceMutatorTest {

    private WorkflowTrace trace;
    private Config config;

    private ReceiveAction receiveHeartbeatAction;
    private ReceiveAction receiveAlertAction;
    private ReceiveAction receiveServerHelloAction;
    private ReceiveAction receiveFinishedAction;

    private SendAction sendHeartbeatAction;
    private SendAction sendAlertAction;
    private SendAction sendClientHelloAction;
    private SendAction sendFinishedAction;

    @BeforeEach
    public void setUp() {
        config = new Config();
        trace = new WorkflowTrace();

        receiveHeartbeatAction = new ReceiveAction();
        receiveAlertAction = new ReceiveAction();
        receiveServerHelloAction = new ReceiveAction();
        receiveFinishedAction = new ReceiveAction();

        receiveHeartbeatAction.setExpectedMessages(new HeartbeatMessage());
        receiveAlertAction.setExpectedMessages(new AlertMessage());
        receiveServerHelloAction.setExpectedMessages(new ServerHelloMessage());
        receiveFinishedAction.setExpectedMessages(new FinishedMessage());

        sendHeartbeatAction = new SendAction(new HeartbeatMessage());
        sendAlertAction = new SendAction(new AlertMessage());
        sendClientHelloAction = new SendAction(new ClientHelloMessage());
        sendFinishedAction = new SendAction(new FinishedMessage());
    }

    @Test
    public void testReplaceSendingMessageProtocolMessage() {
        trace.addTlsAction(sendClientHelloAction);

        ProtocolMessage replaceMsg = new FinishedMessage();
        WorkflowTraceMutator.replaceStaticSendingMessage(
                trace, ProtocolMessageType.HANDSHAKE, replaceMsg);

        assertEquals(
                replaceMsg,
                WorkflowTraceResultUtil.getFirstSentMessage(ProtocolMessageType.HANDSHAKE, trace));
    }

    @Test
    public void testReplaceSendingMessageHandshakeMessage() {
        trace.addTlsAction(sendClientHelloAction);

        HandshakeMessage replaceMsg = new FinishedMessage();
        WorkflowTraceMutator.replaceStaticSendingMessage(
                trace, HandshakeMessageType.CLIENT_HELLO, replaceMsg);

        assertEquals(
                replaceMsg,
                WorkflowTraceResultUtil.getFirstSentMessage(ProtocolMessageType.HANDSHAKE, trace));
    }

    @Test
    public void testDeleteSendingMessageProtocolMessage() {
        trace.addTlsAction(sendClientHelloAction);

        WorkflowTraceMutator.deleteSendingMessage(trace, ProtocolMessageType.ALERT);
        assertEquals(1, trace.getSendingActions().size());

        WorkflowTraceMutator.deleteSendingMessage(trace, ProtocolMessageType.HANDSHAKE);
        assertEquals(0, trace.getSendingActions().size());
    }

    @Test
    public void testDeleteSendingMessageHandshakeMessage() {
        trace.addTlsAction(sendClientHelloAction);

        WorkflowTraceMutator.deleteSendingMessage(trace, HandshakeMessageType.SERVER_HELLO);
        assertEquals(1, trace.getSendingActions().size());

        WorkflowTraceMutator.deleteSendingMessage(trace, HandshakeMessageType.CLIENT_HELLO);
        assertEquals(0, trace.getSendingActions().size());
    }

    @Test
    public void testReplaceReceivingMessageProtocolMessage() throws WorkflowTraceMutationException {
        trace.addTlsAction(receiveServerHelloAction);

        ProtocolMessage replaceMsg = new FinishedMessage();
        WorkflowTraceMutator.replaceReceivingMessage(
                trace, ProtocolMessageType.HANDSHAKE, replaceMsg);

        ReceiveAction action =
                (ReceiveAction)
                        WorkflowTraceResultUtil.getActionsThatReceived(
                                        ProtocolMessageType.HANDSHAKE, trace)
                                .get(0);
        assertEquals(replaceMsg, action.getExpectedMessages().get(0));
    }

    @Test
    public void testReplaceReceivingMessageHandshakeMessage()
            throws WorkflowTraceMutationException {
        trace.addTlsAction(receiveServerHelloAction);

        HandshakeMessage replaceMsg = new FinishedMessage();
        WorkflowTraceMutator.replaceReceivingMessage(
                trace, HandshakeMessageType.SERVER_HELLO, replaceMsg);

        ReceiveAction action =
                (ReceiveAction)
                        WorkflowTraceResultUtil.getActionsThatReceived(
                                        ProtocolMessageType.HANDSHAKE, trace)
                                .get(0);
        assertEquals(replaceMsg, action.getExpectedMessages().get(0));
    }

    @Test
    public void testDeleteReceivingMessageProtocolMessage() throws WorkflowTraceMutationException {
        trace.addTlsAction(receiveServerHelloAction);

        WorkflowTraceMutator.deleteReceivingMessage(trace, ProtocolMessageType.HANDSHAKE);

        List<ReceivingAction> actions =
                WorkflowTraceResultUtil.getActionsThatReceived(
                        ProtocolMessageType.HANDSHAKE, trace);
        assertEquals(0, actions.size());
    }

    @Test
    public void testDeleteReceivingMessageHandshakeMessage() throws WorkflowTraceMutationException {
        trace.addTlsAction(receiveServerHelloAction);

        WorkflowTraceMutator.deleteReceivingMessage(trace, HandshakeMessageType.SERVER_HELLO);

        List<ReceivingAction> actions =
                WorkflowTraceResultUtil.getActionsThatReceived(
                        ProtocolMessageType.HANDSHAKE, trace);
        assertEquals(0, actions.size());
    }

    @Test
    public void testMoreComplexExample() throws WorkflowTraceMutationException {
        trace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(
                        new ServerHelloMessage(config),
                        new CertificateMessage(),
                        new ServerHelloDoneMessage()),
                new SendAction(
                        new ECDHClientKeyExchangeMessage(),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()),
                new ReceiveAction(new FinishedMessage()));

        HandshakeMessage chm = new SrpClientKeyExchangeMessage();

        WorkflowTraceMutator.replaceStaticSendingMessage(trace, HandshakeMessageType.FINISHED, chm);
        assertEquals(chm, ((SendAction) trace.getTlsActions().get(2)).getSentMessages().get(2));

        WorkflowTraceMutator.replaceReceivingMessage(trace, HandshakeMessageType.CERTIFICATE, chm);
        assertEquals(
                chm, ((ReceiveAction) trace.getTlsActions().get(1)).getExpectedMessages().get(1));

        WorkflowTraceMutator.deleteReceivingMessage(trace, HandshakeMessageType.FINISHED);
        assertEquals(3, trace.getTlsActions().size());

        WorkflowTraceMutator.deleteSendingMessage(trace, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        WorkflowTraceMutator.deleteSendingMessage(trace, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        assertEquals(2, trace.getTlsActions().size());
    }

    @Test
    public void testTruncatingAfterReceivingWorkflow() {
        trace.addTlsActions(
                new ReceiveAction(new FinishedMessage()), new SendAction(new FinishedMessage()));

        WorkflowTraceMutator.truncateReceivingAfter(trace, HandshakeMessageType.FINISHED, false);

        assertEquals(1, trace.getTlsActions().size());
        assertTrue(trace.getTlsActions().get(0) instanceof ReceiveAction);
    }

    @Test
    public void testTruncatingAtReceivingWorkflow() {
        trace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage()),
                new ReceiveAction(new FinishedMessage()),
                new SendAction(new FinishedMessage()));

        WorkflowTraceMutator.truncateReceivingAt(trace, HandshakeMessageType.FINISHED, false);
        assertEquals(1, trace.getTlsActions().size());
        assertEquals(
                ClientHelloMessage.class,
                ((ReceiveAction) trace.getTlsActions().get(0))
                        .getExpectedMessages()
                        .get(0)
                        .getClass());
    }

    @Test
    public void testTruncatingAfterSendingWorkflow() {
        trace.addTlsActions(
                new SendAction(new FinishedMessage()), new ReceiveAction(new FinishedMessage()));

        WorkflowTraceMutator.truncateSendingAfter(trace, HandshakeMessageType.FINISHED, false);

        assertEquals(1, trace.getTlsActions().size());
        assertTrue(trace.getTlsActions().get(0) instanceof SendAction);
    }

    @Test
    public void testTruncatingAtSendingWorkflow() {
        trace.addTlsActions(
                new SendAction(new FinishedMessage()), new ReceiveAction(new FinishedMessage()));

        WorkflowTraceMutator.truncateSendingAt(trace, HandshakeMessageType.FINISHED, false);

        assertEquals(0, trace.getTlsActions().size());
    }

    @Test
    public void testTruncateAt() {
        trace.addTlsActions(
                new SendAction(new FinishedMessage()), new ReceiveAction(new FinishedMessage()));

        WorkflowTraceMutator.truncateAt(trace, HandshakeMessageType.FINISHED, false);

        assertEquals(0, trace.getTlsActions().size());
    }

    @Test
    public void testTruncatingWorkflow() {
        trace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(
                        new ServerHelloMessage(config),
                        new CertificateMessage(),
                        new ServerHelloDoneMessage()),
                new SendAction(
                        new ECDHClientKeyExchangeMessage(),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()),
                new ReceiveAction(new FinishedMessage()));

        // Delete after first finished message
        WorkflowTraceMutator.truncateReceivingAt(trace, HandshakeMessageType.FINISHED, false);
        assertEquals(3, trace.getTlsActions().size());
        assertEquals(3, ((SendAction) trace.getTlsActions().get(2)).getSentMessages().size());

        // Delete after ServerHelloDoneMessage
        WorkflowTraceMutator.truncateAfter(trace, HandshakeMessageType.SERVER_HELLO_DONE, false);
        assertEquals(2, trace.getTlsActions().size());
        assertTrue(trace.getTlsActions().get(1) instanceof ReceiveAction);
        assertEquals(
                3, ((ReceiveAction) trace.getTlsActions().get(1)).getExpectedMessages().size());

        // Delete from ServerHello
        WorkflowTraceMutator.truncateAt(trace, HandshakeMessageType.SERVER_HELLO, false);
        assertEquals(1, trace.getTlsActions().size());
    }

    @Test
    public void testTruncatingWorkflowWithDynamicActions() {
        trace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveTillAction(new ServerHelloDoneMessage()),
                new SendDynamicClientKeyExchangeAction(),
                new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()),
                new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));

        // Delete after first ClientKeyExchange message
        WorkflowTraceMutator.truncateAfter(trace, HandshakeMessageType.CLIENT_KEY_EXCHANGE, false);
        assertEquals(3, trace.getTlsActions().size());

        // Delete ClientKeyEchange message
        WorkflowTraceMutator.truncateAt(trace, HandshakeMessageType.CLIENT_KEY_EXCHANGE, false);
        assertEquals(2, trace.getTlsActions().size());

        WorkflowTraceMutator.truncateAt(trace, HandshakeMessageType.SERVER_HELLO_DONE, false);
        assertEquals(1, trace.getTlsActions().size());
    }
}
