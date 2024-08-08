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
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SrpClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.StaticReceivingAction;
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

    private SendAction sendClientHelloAction;

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

        sendClientHelloAction = new SendAction(new ClientHelloMessage());
    }

    @Test
    public void testReplaceSendingMessageProtocolMessage() {
        trace.addTlsAction(sendClientHelloAction);

        ProtocolMessage replaceMsg = new FinishedMessage();
        WorkflowTraceMutator.replaceStaticSendingMessage(
                trace, ProtocolMessageType.HANDSHAKE, replaceMsg);

        assertEquals(
                replaceMsg,
                WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                        trace, ProtocolMessageType.HANDSHAKE));
    }

    @Test
    public void testReplaceSendingMessageHandshakeMessage() {
        trace.addTlsAction(sendClientHelloAction);

        HandshakeMessage replacementMessage = new FinishedMessage();
        WorkflowTraceMutator.replaceStaticSendingMessage(
                trace, HandshakeMessageType.CLIENT_HELLO, replacementMessage);

        assertEquals(
                replacementMessage,
                WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                        trace, ProtocolMessageType.HANDSHAKE));
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
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredReceiveAction(
                                trace, ProtocolMessageType.HANDSHAKE);
        assertEquals(replaceMsg, action.getExpectedMessages().get(0));
    }

    @Test
    public void testReplaceReceivingMessageHandshakeMessage()
            throws WorkflowTraceMutationException {
        trace.addTlsAction(receiveServerHelloAction);

        HandshakeMessage replaceMsg = new FinishedMessage();
        WorkflowTraceMutator.replaceReceivingMessage(
                trace, HandshakeMessageType.SERVER_HELLO, replaceMsg);

        StaticReceivingAction action =
                WorkflowTraceConfigurationUtil.getFirstStaticConfiguredReceiveAction(
                        trace, ProtocolMessageType.HANDSHAKE);
        assertEquals(replaceMsg, action.getExpectedList(ProtocolMessage.class).get(0));
    }

    @Test
    public void testDeleteReceivingMessageProtocolMessage() throws WorkflowTraceMutationException {
        trace.addTlsAction(receiveServerHelloAction);

        WorkflowTraceMutator.deleteReceivingMessage(trace, ProtocolMessageType.HANDSHAKE);

        List<ReceivingAction> actions =
                WorkflowTraceResultUtil.getActionsThatReceived(
                        trace, ProtocolMessageType.HANDSHAKE);
        assertEquals(0, actions.size());
    }

    @Test
    public void testDeleteReceivingMessageHandshakeMessage() throws WorkflowTraceMutationException {
        trace.addTlsAction(receiveServerHelloAction);

        WorkflowTraceMutator.deleteReceivingMessage(trace, HandshakeMessageType.SERVER_HELLO);

        List<ReceivingAction> actions =
                WorkflowTraceResultUtil.getActionsThatReceived(
                        trace, ProtocolMessageType.HANDSHAKE);
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

        HandshakeMessage srpMessage = new SrpClientKeyExchangeMessage();

        WorkflowTraceMutator.replaceStaticSendingMessage(
                trace, HandshakeMessageType.FINISHED, srpMessage);
        assertEquals(
                srpMessage,
                ((SendAction) trace.getTlsActions().get(2))
                        .getConfiguredList(ProtocolMessage.class)
                        .get(2));

        WorkflowTraceMutator.replaceReceivingMessage(
                trace, HandshakeMessageType.CERTIFICATE, srpMessage);
        assertEquals(
                srpMessage,
                ((ReceiveAction) trace.getTlsActions().get(1)).getExpectedMessages().get(1));

        WorkflowTraceMutator.deleteReceivingMessage(trace, HandshakeMessageType.FINISHED);
        assertEquals(3, trace.getTlsActions().size());

        WorkflowTraceMutator.deleteSendingMessage(trace, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        assertEquals(3, trace.getTlsActions().size());
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
        assertEquals(
                3,
                ((SendAction) trace.getTlsActions().get(2))
                        .getConfiguredList(ProtocolMessage.class)
                        .size());

        // Delete after ServerHelloDoneMessage
        WorkflowTraceMutator.truncateReceivingAfter(
                trace, HandshakeMessageType.SERVER_HELLO_DONE, false);
        assertEquals(2, trace.getTlsActions().size());
        assertTrue(trace.getTlsActions().get(1) instanceof ReceiveAction);
        assertEquals(
                3, ((ReceiveAction) trace.getTlsActions().get(1)).getExpectedMessages().size());
    }

    /*     @Test
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
    } */
}
