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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.action.DummyReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.DummySendingAction;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class WorkflowTraceResultUtilTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private WorkflowTrace trace;
    private Config config;

    private DummyReceivingAction rcvHeartbeat;
    private DummyReceivingAction rcvAlertMessage;
    private DummyReceivingAction rcvServerHello;
    private DummyReceivingAction rcvFinishedMessage;
    private DummyReceivingAction rcvMultipleProtocolMessages;
    private DummyReceivingAction rcvMultipleHandshakeMessages;
    private DummyReceivingAction rcvMultipleRecords;

    private HeartbeatMessage msgHeartbeatMessageWithLength;
    private ServerHelloMessage msgServerHelloWithHeartbeatExtension;
    private ServerHelloMessage msgServerHelloWithEncryptThenMacExtension;
    private ServerHelloMessage msgServerHelloMessageWithCipherSuite;

    private Record recWithLength;

    private DummySendingAction sHeartbeat;
    private DummySendingAction sAlertMessage;
    private DummySendingAction sClientHello;
    private DummySendingAction sFinishedMessage;
    private DummySendingAction sHeartbeatExtension;
    private DummySendingAction sEncryptThenMacExtension;

    @BeforeEach
    public void setUp() {
        config = new Config();
        trace = new WorkflowTrace();

        rcvHeartbeat = new DummyReceivingAction();
        rcvAlertMessage = new DummyReceivingAction();
        rcvServerHello = new DummyReceivingAction();
        rcvFinishedMessage = new DummyReceivingAction();
        rcvMultipleProtocolMessages = new DummyReceivingAction();
        rcvMultipleHandshakeMessages = new DummyReceivingAction();
        rcvMultipleRecords = new DummyReceivingAction();

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

        rcvHeartbeat.setExpectedMessages(new HeartbeatMessage());
        rcvAlertMessage.setExpectedMessages(new AlertMessage());
        rcvServerHello.setExpectedMessages(new ServerHelloMessage());
        rcvFinishedMessage.setExpectedMessages(new FinishedMessage());
        rcvMultipleProtocolMessages.setExpectedMessages(
                new HeartbeatMessage(), new HeartbeatMessage(), msgHeartbeatMessageWithLength);
        rcvMultipleHandshakeMessages.setExpectedMessages(
                new ServerHelloMessage(),
                new HeartbeatMessage(),
                msgServerHelloMessageWithCipherSuite);
        rcvMultipleRecords.setExpectedRecords(List.of(new Record(), new Record(), recWithLength));

        sHeartbeat = new DummySendingAction();
        sAlertMessage = new DummySendingAction();
        sClientHello = new DummySendingAction();
        sFinishedMessage = new DummySendingAction();
        sHeartbeatExtension = new DummySendingAction();
        sEncryptThenMacExtension = new DummySendingAction();

        sHeartbeat.setConfiguredMessages(new HeartbeatMessage());
        sAlertMessage.setConfiguredMessages(new AlertMessage());
        sClientHello.setConfiguredMessages(new ClientHelloMessage());
        sFinishedMessage.setConfiguredMessages(new FinishedMessage());
        sHeartbeatExtension.setConfiguredMessages(msgServerHelloWithHeartbeatExtension);
        sEncryptThenMacExtension.setConfiguredMessages(msgServerHelloWithEncryptThenMacExtension);
    }

    @Test
    public void testGetLastReceivedMessage() {
        assertNull(
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        ProtocolMessageType.HEARTBEAT, trace));

        trace.addTlsAction(rcvMultipleProtocolMessages);

        assertNotSame(
                rcvMultipleProtocolMessages.getExpectedMessages().get(0),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        ProtocolMessageType.HEARTBEAT, trace));
        assertNotSame(
                rcvMultipleProtocolMessages.getExpectedMessages().get(1),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        ProtocolMessageType.HEARTBEAT, trace));
        assertSame(
                rcvMultipleProtocolMessages.getExpectedMessages().get(2),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        ProtocolMessageType.HEARTBEAT, trace));

        assertNull(
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        HandshakeMessageType.SERVER_HELLO, trace));

        trace.addTlsAction(rcvMultipleHandshakeMessages);

        assertNotSame(
                rcvMultipleHandshakeMessages.getExpectedMessages().get(0),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        HandshakeMessageType.SERVER_HELLO, trace));
        assertNotSame(
                rcvMultipleHandshakeMessages.getExpectedMessages().get(1),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        HandshakeMessageType.SERVER_HELLO, trace));
        assertSame(
                rcvMultipleHandshakeMessages.getExpectedMessages().get(2),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        HandshakeMessageType.SERVER_HELLO, trace));
    }

    @Test
    public void testDidReceiveMessage() {
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertFalse(WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(
                        HandshakeMessageType.SERVER_HELLO, trace));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(rcvHeartbeat);

        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertFalse(WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(
                        HandshakeMessageType.SERVER_HELLO, trace));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(rcvAlertMessage);

        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(
                        HandshakeMessageType.SERVER_HELLO, trace));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(rcvServerHello);

        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertTrue(
                WorkflowTraceResultUtil.didReceiveMessage(
                        HandshakeMessageType.SERVER_HELLO, trace));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(rcvFinishedMessage);

        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        assertTrue(
                WorkflowTraceResultUtil.didReceiveMessage(
                        HandshakeMessageType.SERVER_HELLO, trace));
        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace));
    }

    @Test
    public void testDidSendMessage() {
        assertFalse(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(
                WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(sHeartbeat);

        assertTrue(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(
                WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(sAlertMessage);

        assertTrue(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertFalse(
                WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(sClientHello);

        assertTrue(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertTrue(
                WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));

        trace.addTlsAction(sFinishedMessage);

        assertTrue(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.HEARTBEAT, trace));
        assertTrue(WorkflowTraceResultUtil.didSendMessage(ProtocolMessageType.ALERT, trace));
        assertTrue(
                WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.CLIENT_HELLO, trace));
        assertTrue(WorkflowTraceResultUtil.didSendMessage(HandshakeMessageType.FINISHED, trace));
    }

    @Test
    public void testGetLastReceivedRecord() {
        assertNull(WorkflowTraceResultUtil.getLastReceivedRecord(trace));

        trace.addTlsAction(rcvMultipleRecords);

        assertNotSame(
                rcvMultipleRecords.getReceivedRecords().get(0),
                WorkflowTraceResultUtil.getLastReceivedRecord(trace));
        assertNotSame(
                rcvMultipleRecords.getReceivedRecords().get(1),
                WorkflowTraceResultUtil.getLastReceivedRecord(trace));
        assertSame(
                rcvMultipleRecords.getReceivedRecords().get(2),
                WorkflowTraceResultUtil.getLastReceivedRecord(trace));
    }

    @Test
    public void testGetFirstSentExtension() {
        assertNull(WorkflowTraceResultUtil.getFirstSentExtension(ExtensionType.HEARTBEAT, trace));
        assertNull(
                WorkflowTraceResultUtil.getFirstSentExtension(
                        ExtensionType.ENCRYPT_THEN_MAC, trace));

        trace.addTlsAction(sHeartbeatExtension);

        assertSame(
                msgServerHelloWithHeartbeatExtension.getExtensions().get(0),
                WorkflowTraceResultUtil.getFirstSentExtension(ExtensionType.HEARTBEAT, trace));
        assertNull(
                WorkflowTraceResultUtil.getFirstSentExtension(
                        ExtensionType.ENCRYPT_THEN_MAC, trace));

        trace.addTlsAction(sEncryptThenMacExtension);

        assertSame(
                msgServerHelloWithHeartbeatExtension.getExtensions().get(0),
                WorkflowTraceResultUtil.getFirstSentExtension(ExtensionType.HEARTBEAT, trace));
        assertSame(
                msgServerHelloWithEncryptThenMacExtension.getExtensions().get(0),
                WorkflowTraceResultUtil.getFirstSentExtension(
                        ExtensionType.ENCRYPT_THEN_MAC, trace));
    }

    private void printWorkflowTrace(String pre, WorkflowTrace trace) {
        LOGGER.debug(pre);
        try {
            LOGGER.debug(WorkflowTraceSerializer.write(trace));
        } catch (JAXBException | IOException ex) {
            LOGGER.error(ex);
        }
    }

    @Test
    public void testGetActionsThatSent() {
        assertEquals(
                0,
                WorkflowTraceResultUtil.getActionsThatSent(ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                0,
                WorkflowTraceResultUtil.getActionsThatSent(HandshakeMessageType.CLIENT_HELLO, trace)
                        .size());

        trace.addTlsAction(sClientHello);

        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(HandshakeMessageType.CLIENT_HELLO, trace)
                        .size());
        assertEquals(
                sClientHello,
                WorkflowTraceResultUtil.getActionsThatSent(HandshakeMessageType.CLIENT_HELLO, trace)
                        .get(0));
        assertEquals(
                sClientHello,
                WorkflowTraceResultUtil.getActionsThatSent(ProtocolMessageType.HANDSHAKE, trace)
                        .get(0));

        trace.addTlsAction(sHeartbeat);

        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(HandshakeMessageType.CLIENT_HELLO, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(ProtocolMessageType.HEARTBEAT, trace)
                        .size());
        assertEquals(
                sHeartbeat,
                WorkflowTraceResultUtil.getActionsThatSent(ProtocolMessageType.HEARTBEAT, trace)
                        .get(0));
    }

    @Test
    public void testGetActionsThatReceived() {
        assertEquals(
                0,
                WorkflowTraceResultUtil.getActionsThatReceived(ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                0,
                WorkflowTraceResultUtil.getActionsThatReceived(
                                HandshakeMessageType.CLIENT_HELLO, trace)
                        .size());

        DummyReceivingAction serverHelloRAction =
                new DummyReceivingAction(new ServerHelloMessage());
        trace.addTlsAction(serverHelloRAction);

        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(
                                HandshakeMessageType.SERVER_HELLO, trace)
                        .size());
        assertEquals(
                serverHelloRAction,
                WorkflowTraceResultUtil.getActionsThatReceived(
                                HandshakeMessageType.SERVER_HELLO, trace)
                        .get(0));
        assertEquals(
                serverHelloRAction,
                WorkflowTraceResultUtil.getActionsThatReceived(ProtocolMessageType.HANDSHAKE, trace)
                        .get(0));

        DummyReceivingAction alertRAction = new DummyReceivingAction(new AlertMessage());
        trace.addTlsAction(alertRAction);

        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(ProtocolMessageType.HANDSHAKE, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(
                                HandshakeMessageType.SERVER_HELLO, trace)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(ProtocolMessageType.ALERT, trace)
                        .size());
        assertEquals(
                alertRAction,
                WorkflowTraceResultUtil.getActionsThatReceived(ProtocolMessageType.ALERT, trace)
                        .get(0));
    }

    @Test
    public void testGetFirstActionThatReceived3() {
        trace.addTlsActions(
                new DummySendingAction(new FinishedMessage()),
                new DummyReceivingAction(new FinishedMessage()));
        assertTrue(
                WorkflowTraceResultUtil.getFirstActionThatReceived(
                                HandshakeMessageType.FINISHED, trace)
                        instanceof DummyReceivingAction);
    }

    @Test
    public void testGetFirstActionThatReceived2() {
        trace.addTlsActions(
                new DummyReceivingAction(new FinishedMessage()),
                new DummySendingAction(new FinishedMessage()));
        assertTrue(
                WorkflowTraceResultUtil.getFirstActionThatReceived(
                                HandshakeMessageType.FINISHED, trace)
                        instanceof DummyReceivingAction);
    }

    @Test
    public void testGetFirstActionThatReceived() {
        trace.addTlsActions(
                new DummyReceivingAction(new FinishedMessage()),
                new DummyReceivingAction(new FinishedMessage()),
                new DummySendingAction(new FinishedMessage()),
                new DummySendingAction(new FinishedMessage()));
        assertEquals(
                trace.getTlsActions().get(0),
                WorkflowTraceResultUtil.getFirstActionThatReceived(
                        HandshakeMessageType.FINISHED, trace));
    }

    @Test
    public void testGetFirstActionThatSent() {
        trace.addTlsActions(
                new DummyReceivingAction(new FinishedMessage()),
                new DummyReceivingAction(new FinishedMessage()),
                new DummySendingAction(new FinishedMessage()),
                new DummySendingAction(new FinishedMessage()));
        assertEquals(
                trace.getTlsActions().get(2),
                WorkflowTraceResultUtil.getFirstActionThatSent(
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
        printWorkflowTrace("after load:", trace);

        WorkflowTraceNormalizer n = new WorkflowTraceNormalizer();
        n.normalize(trace, config);
        String actual = WorkflowTraceSerializer.write(trace);
        LOGGER.debug(actual);
        actual = WorkflowTraceSerializer.write(trace);
        LOGGER.debug(actual);
    }
}
