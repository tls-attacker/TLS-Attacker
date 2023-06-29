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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class WorkflowTraceUtilTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private WorkflowTrace trace;
    private Config config;

    private ReceiveAction rcvHeartbeat;
    private ReceiveAction rcvAlertMessage;
    private ReceiveAction rcvServerHello;
    private ReceiveAction rcvFinishedMessage;
    private ReceiveAction rcvMultipleProtocolMessages;
    private ReceiveAction rcvMultipleHandshakeMessages;
    private ReceiveAction rcvMultipleRecords;

    private HeartbeatMessage msgHeartbeatMessageWithLength;
    private ServerHelloMessage msgServerHelloWithHeartbeatExtension;
    private ServerHelloMessage msgServerHelloWithEncryptThenMacExtension;
    private ServerHelloMessage msgServerHelloMessageWithCipherSuite;

    private Record recWithLength;

    private SendAction sHeartbeat;
    private SendAction sAlertMessage;
    private SendAction sClientHello;
    private SendAction sFinishedMessage;
    private SendAction sHeartbeatExtension;
    private SendAction sEncryptThenMacExtension;

    @BeforeEach
    public void setUp() {
        config = Config.createConfig();
        trace = new WorkflowTrace();

        rcvHeartbeat = new ReceiveAction();
        rcvAlertMessage = new ReceiveAction();
        rcvServerHello = new ReceiveAction();
        rcvFinishedMessage = new ReceiveAction();
        rcvMultipleProtocolMessages = new ReceiveAction();
        rcvMultipleHandshakeMessages = new ReceiveAction();
        rcvMultipleRecords = new ReceiveAction();

        msgHeartbeatMessageWithLength = new HeartbeatMessage();
        msgHeartbeatMessageWithLength.setPayloadLength(42);
        msgServerHelloMessageWithCipherSuite = new ServerHelloMessage();
        msgServerHelloMessageWithCipherSuite.setSelectedCipherSuite(
                CipherSuite.TLS_AES_128_GCM_SHA256.getByteValue());
        msgServerHelloWithHeartbeatExtension = new ServerHelloMessage();
        msgServerHelloWithHeartbeatExtension.addExtension(new HeartbeatExtensionMessage());
        msgServerHelloWithEncryptThenMacExtension = new ServerHelloMessage();
        msgServerHelloWithEncryptThenMacExtension.addExtension(
                new EncryptThenMacExtensionMessage());

        recWithLength = new Record();
        recWithLength.setLength(42);

        rcvHeartbeat.setMessages(new HeartbeatMessage());
        rcvAlertMessage.setMessages(new AlertMessage());
        rcvServerHello.setMessages(new ServerHelloMessage());
        rcvFinishedMessage.setMessages(new FinishedMessage());
        rcvMultipleProtocolMessages.setMessages(
                new HeartbeatMessage(), new HeartbeatMessage(), msgHeartbeatMessageWithLength);
        rcvMultipleHandshakeMessages.setMessages(
                new ServerHelloMessage(),
                new HeartbeatMessage(),
                msgServerHelloMessageWithCipherSuite);
        rcvMultipleRecords.setRecords(new Record(), new Record(), recWithLength);

        sHeartbeat = new SendAction();
        sAlertMessage = new SendAction();
        sClientHello = new SendAction();
        sFinishedMessage = new SendAction();
        sHeartbeatExtension = new SendAction();
        sEncryptThenMacExtension = new SendAction();

        sHeartbeat.setMessages(new HeartbeatMessage());
        sAlertMessage.setMessages(new AlertMessage());
        sClientHello.setMessages(new ClientHelloMessage());
        sFinishedMessage.setMessages(new FinishedMessage());
        sHeartbeatExtension.setMessages(msgServerHelloWithHeartbeatExtension);
        sEncryptThenMacExtension.setMessages(msgServerHelloWithEncryptThenMacExtension);
    }

    @Test
    public void testGetLastReceivedMessage() {
        assertNull(WorkflowTraceUtil.getLastReceivedMessage(ProtocolMessageType.HEARTBEAT, trace));

        trace.addTlsAction(rcvMultipleProtocolMessages);

        assertNotSame(
                rcvMultipleProtocolMessages.getMessages().get(0),
                WorkflowTraceUtil.getLastReceivedMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertNotSame(
                rcvMultipleProtocolMessages.getMessages().get(1),
                WorkflowTraceUtil.getLastReceivedMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertSame(
                rcvMultipleProtocolMessages.getMessages().get(2),
                WorkflowTraceUtil.getLastReceivedMessage(ProtocolMessageType.HEARTBEAT, trace));

        assertNull(
                WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.SERVER_HELLO, trace));

        trace.addTlsAction(rcvMultipleHandshakeMessages);

        assertNotSame(
                rcvMultipleHandshakeMessages.getMessages().get(0),
                WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.SERVER_HELLO, trace));
        assertNotSame(
                rcvMultipleHandshakeMessages.getMessages().get(1),
                WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.SERVER_HELLO, trace));
        assertSame(
                rcvMultipleHandshakeMessages.getMessages().get(2),
                WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.SERVER_HELLO, trace));
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

    @Test
    public void testGetLastReceivedRecord() {
        assertNull(WorkflowTraceUtil.getLastReceivedRecord(trace));

        trace.addTlsAction(rcvMultipleRecords);

        assertNotSame(
                rcvMultipleRecords.getRecords().get(0),
                WorkflowTraceUtil.getLastReceivedRecord(trace));
        assertNotSame(
                rcvMultipleRecords.getRecords().get(1),
                WorkflowTraceUtil.getLastReceivedRecord(trace));
        assertSame(
                rcvMultipleRecords.getRecords().get(2),
                WorkflowTraceUtil.getLastReceivedRecord(trace));
    }

    @Test
    public void testGetFirstSendExtension() {
        assertNull(WorkflowTraceUtil.getFirstSendExtension(ExtensionType.HEARTBEAT, trace));
        assertNull(WorkflowTraceUtil.getFirstSendExtension(ExtensionType.ENCRYPT_THEN_MAC, trace));

        trace.addTlsAction(sHeartbeatExtension);

        assertSame(
                msgServerHelloWithHeartbeatExtension.getExtensions().get(0),
                WorkflowTraceUtil.getFirstSendExtension(ExtensionType.HEARTBEAT, trace));
        assertNull(WorkflowTraceUtil.getFirstSendExtension(ExtensionType.ENCRYPT_THEN_MAC, trace));

        trace.addTlsAction(sEncryptThenMacExtension);

        assertSame(
                msgServerHelloWithHeartbeatExtension.getExtensions().get(0),
                WorkflowTraceUtil.getFirstSendExtension(ExtensionType.HEARTBEAT, trace));
        assertSame(
                msgServerHelloWithEncryptThenMacExtension.getExtensions().get(0),
                WorkflowTraceUtil.getFirstSendExtension(ExtensionType.ENCRYPT_THEN_MAC, trace));
    }

    private void pwf(String pre, WorkflowTrace trace) {
        LOGGER.info(pre);
        try {
            LOGGER.info(WorkflowTraceSerializer.write(trace));
        } catch (JAXBException | IOException ex) {
            java.util.logging.Logger.getLogger(WorkflowTraceUtilTest.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testGetSendingActionsForMessage() {
        assertEquals(
                0,
                WorkflowTraceUtil.getSendingActionsForMessage(ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                0,
                WorkflowTraceUtil.getSendingActionsForMessage(
                                HandshakeMessageType.CLIENT_HELLO, trace)
                        .size());

        trace.addTlsAction(sClientHello);

        assertEquals(
                1,
                WorkflowTraceUtil.getSendingActionsForMessage(ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceUtil.getSendingActionsForMessage(
                                HandshakeMessageType.CLIENT_HELLO, trace)
                        .size());
        assertEquals(
                sClientHello,
                WorkflowTraceUtil.getSendingActionsForMessage(
                                HandshakeMessageType.CLIENT_HELLO, trace)
                        .get(0));
        assertEquals(
                sClientHello,
                WorkflowTraceUtil.getSendingActionsForMessage(ProtocolMessageType.HANDSHAKE, trace)
                        .get(0));

        trace.addTlsAction(sHeartbeat);

        assertEquals(
                1,
                WorkflowTraceUtil.getSendingActionsForMessage(ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceUtil.getSendingActionsForMessage(
                                HandshakeMessageType.CLIENT_HELLO, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceUtil.getSendingActionsForMessage(ProtocolMessageType.HEARTBEAT, trace)
                        .size());
        assertEquals(
                sHeartbeat,
                WorkflowTraceUtil.getSendingActionsForMessage(ProtocolMessageType.HEARTBEAT, trace)
                        .get(0));
    }

    @Test
    public void testGetReceivingActionsForMessage() {
        assertEquals(
                0,
                WorkflowTraceUtil.getReceivingActionsForMessage(
                                ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                0,
                WorkflowTraceUtil.getReceivingActionsForMessage(
                                HandshakeMessageType.CLIENT_HELLO, trace)
                        .size());

        ReceiveAction serverHelloRAction = new ReceiveAction(new ServerHelloMessage());
        trace.addTlsAction(serverHelloRAction);

        assertEquals(
                1,
                WorkflowTraceUtil.getReceivingActionsForMessage(
                                ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceUtil.getReceivingActionsForMessage(
                                HandshakeMessageType.SERVER_HELLO, trace)
                        .size());
        assertEquals(
                serverHelloRAction,
                WorkflowTraceUtil.getReceivingActionsForMessage(
                                HandshakeMessageType.SERVER_HELLO, trace)
                        .get(0));
        assertEquals(
                serverHelloRAction,
                WorkflowTraceUtil.getReceivingActionsForMessage(
                                ProtocolMessageType.HANDSHAKE, trace)
                        .get(0));

        ReceiveAction alertRAction = new ReceiveAction(new AlertMessage());
        trace.addTlsAction(alertRAction);

        assertEquals(
                1,
                WorkflowTraceUtil.getReceivingActionsForMessage(
                                ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceUtil.getReceivingActionsForMessage(
                                HandshakeMessageType.SERVER_HELLO, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceUtil.getReceivingActionsForMessage(ProtocolMessageType.ALERT, trace)
                        .size());
        assertEquals(
                alertRAction,
                WorkflowTraceUtil.getReceivingActionsForMessage(ProtocolMessageType.ALERT, trace)
                        .get(0));
    }

    @Test
    public void testGetFirstActionForMessage() {
        trace.addTlsActions(
                new SendAction(new FinishedMessage()), new ReceiveAction(new FinishedMessage()));
        assertTrue(
                WorkflowTraceUtil.getFirstActionForMessage(HandshakeMessageType.FINISHED, trace)
                        instanceof SendAction);
    }

    @Test
    public void testGetFirstActionForMessage2() {
        trace.addTlsActions(
                new ReceiveAction(new FinishedMessage()), new SendAction(new FinishedMessage()));
        assertTrue(
                WorkflowTraceUtil.getFirstActionForMessage(HandshakeMessageType.FINISHED, trace)
                        instanceof ReceiveAction);
    }

    @Test
    public void testGetFirstReceivingActionForMessage() {
        trace.addTlsActions(
                new ReceiveAction(new FinishedMessage()),
                new ReceiveAction(new FinishedMessage()),
                new SendAction(new FinishedMessage()),
                new SendAction(new FinishedMessage()));
        assertEquals(
                trace.getTlsActions().get(0),
                WorkflowTraceUtil.getFirstReceivingActionForMessage(
                        HandshakeMessageType.FINISHED, trace));
    }

    @Test
    public void testGetFirstSendingActionForMessage() {
        trace.addTlsActions(
                new ReceiveAction(new FinishedMessage()),
                new ReceiveAction(new FinishedMessage()),
                new SendAction(new FinishedMessage()),
                new SendAction(new FinishedMessage()));
        assertEquals(
                trace.getTlsActions().get(2),
                WorkflowTraceUtil.getFirstSendingActionForMessage(
                        HandshakeMessageType.FINISHED, trace));
    }

    @Test
    public void handleDefaultsOfGoodTraceWithDefaultAliasSucceeds()
            throws JAXBException, IOException, XMLStreamException {
        try (InputStream is =
                Config.class.getResourceAsStream("/test_good_workflow_trace_default_alias.xml")) {
            trace = WorkflowTraceSerializer.secureRead(is);
        }
        assertNotNull(trace);
        pwf("after load:", trace);

        WorkflowTraceNormalizer n = new WorkflowTraceNormalizer();
        n.normalize(trace, config);
        String actual = WorkflowTraceSerializer.write(trace);
        LOGGER.info(actual);
        actual = WorkflowTraceSerializer.write(trace);
        LOGGER.info(actual);
    }
}
