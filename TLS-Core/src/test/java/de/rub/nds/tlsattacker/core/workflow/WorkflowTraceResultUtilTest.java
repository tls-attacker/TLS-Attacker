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
                        trace, ProtocolMessageType.HEARTBEAT));

        trace.addTlsAction(rcvMultipleProtocolMessages);

        assertNotSame(
                rcvMultipleProtocolMessages.getExpectedMessages().get(0),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        trace, ProtocolMessageType.HEARTBEAT));
        assertNotSame(
                rcvMultipleProtocolMessages.getExpectedMessages().get(1),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        trace, ProtocolMessageType.HEARTBEAT));
        assertSame(
                rcvMultipleProtocolMessages.getExpectedMessages().get(2),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        trace, ProtocolMessageType.HEARTBEAT));

        assertNull(
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        trace, HandshakeMessageType.SERVER_HELLO));

        trace.addTlsAction(rcvMultipleHandshakeMessages);

        assertNotSame(
                rcvMultipleHandshakeMessages.getExpectedMessages().get(0),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        trace, HandshakeMessageType.SERVER_HELLO));
        assertNotSame(
                rcvMultipleHandshakeMessages.getExpectedMessages().get(1),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        trace, HandshakeMessageType.SERVER_HELLO));
        assertSame(
                rcvMultipleHandshakeMessages.getExpectedMessages().get(2),
                WorkflowTraceResultUtil.getLastReceivedMessage(
                        trace, HandshakeMessageType.SERVER_HELLO));
    }

    @Test
    public void testDidReceiveMessage() {
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertFalse(WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.ALERT));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.SERVER_HELLO));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.FINISHED));

        trace.addTlsAction(rcvHeartbeat);

        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertFalse(WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.ALERT));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.SERVER_HELLO));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.FINISHED));

        trace.addTlsAction(rcvAlertMessage);

        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.ALERT));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.SERVER_HELLO));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.FINISHED));

        trace.addTlsAction(rcvServerHello);

        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.ALERT));
        assertTrue(
                WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.SERVER_HELLO));
        assertFalse(
                WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.FINISHED));

        trace.addTlsAction(rcvFinishedMessage);

        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(trace, ProtocolMessageType.ALERT));
        assertTrue(
                WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.SERVER_HELLO));
        assertTrue(WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.FINISHED));
    }

    @Test
    public void testDidSendMessage() {
        assertFalse(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.ALERT));
        assertFalse(
                WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.CLIENT_HELLO));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.FINISHED));

        trace.addTlsAction(sHeartbeat);

        assertTrue(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.ALERT));
        assertFalse(
                WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.CLIENT_HELLO));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.FINISHED));

        trace.addTlsAction(sAlertMessage);

        assertTrue(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertTrue(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.ALERT));
        assertFalse(
                WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.CLIENT_HELLO));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.FINISHED));

        trace.addTlsAction(sClientHello);

        assertTrue(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertTrue(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.ALERT));
        assertTrue(
                WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.CLIENT_HELLO));
        assertFalse(WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.FINISHED));

        trace.addTlsAction(sFinishedMessage);

        assertTrue(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.HEARTBEAT));
        assertTrue(WorkflowTraceResultUtil.didSendMessage(trace, ProtocolMessageType.ALERT));
        assertTrue(
                WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.CLIENT_HELLO));
        assertTrue(WorkflowTraceResultUtil.didSendMessage(trace, HandshakeMessageType.FINISHED));
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
        assertNull(WorkflowTraceResultUtil.getFirstSentExtension(trace, ExtensionType.HEARTBEAT));
        assertNull(
                WorkflowTraceResultUtil.getFirstSentExtension(
                        trace, ExtensionType.ENCRYPT_THEN_MAC));

        trace.addTlsAction(sHeartbeatExtension);

        assertSame(
                msgServerHelloWithHeartbeatExtension.getExtensions().get(0),
                WorkflowTraceResultUtil.getFirstSentExtension(trace, ExtensionType.HEARTBEAT));
        assertNull(
                WorkflowTraceResultUtil.getFirstSentExtension(
                        trace, ExtensionType.ENCRYPT_THEN_MAC));

        trace.addTlsAction(sEncryptThenMacExtension);

        assertSame(
                msgServerHelloWithHeartbeatExtension.getExtensions().get(0),
                WorkflowTraceResultUtil.getFirstSentExtension(trace, ExtensionType.HEARTBEAT));
        assertSame(
                msgServerHelloWithEncryptThenMacExtension.getExtensions().get(0),
                WorkflowTraceResultUtil.getFirstSentExtension(
                        trace, ExtensionType.ENCRYPT_THEN_MAC));
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
                WorkflowTraceResultUtil.getActionsThatSent(trace, ProtocolMessageType.HANDSHAKE)
                        .size());
        assertEquals(
                0,
                WorkflowTraceResultUtil.getActionsThatSent(trace, HandshakeMessageType.CLIENT_HELLO)
                        .size());

        trace.addTlsAction(sClientHello);

        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(trace, ProtocolMessageType.HANDSHAKE)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(trace, HandshakeMessageType.CLIENT_HELLO)
                        .size());
        assertEquals(
                sClientHello,
                WorkflowTraceResultUtil.getActionsThatSent(trace, HandshakeMessageType.CLIENT_HELLO)
                        .get(0));
        assertEquals(
                sClientHello,
                WorkflowTraceResultUtil.getActionsThatSent(trace, ProtocolMessageType.HANDSHAKE)
                        .get(0));

        trace.addTlsAction(sHeartbeat);

        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(trace, ProtocolMessageType.HANDSHAKE)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(trace, HandshakeMessageType.CLIENT_HELLO)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatSent(trace, ProtocolMessageType.HEARTBEAT)
                        .size());
        assertEquals(
                sHeartbeat,
                WorkflowTraceResultUtil.getActionsThatSent(trace, ProtocolMessageType.HEARTBEAT)
                        .get(0));
    }

    @Test
    public void testGetActionsThatReceived() {
        assertEquals(
                0,
                WorkflowTraceResultUtil.getActionsThatReceived(trace, ProtocolMessageType.HANDSHAKE)
                        .size());
        assertEquals(
                0,
                WorkflowTraceResultUtil.getActionsThatReceived(
                                trace, HandshakeMessageType.CLIENT_HELLO)
                        .size());

        DummyReceivingAction serverHelloRAction =
                new DummyReceivingAction(new ServerHelloMessage());
        trace.addTlsAction(serverHelloRAction);

        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(trace, ProtocolMessageType.HANDSHAKE)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(
                                trace, HandshakeMessageType.SERVER_HELLO)
                        .size());
        assertEquals(
                serverHelloRAction,
                WorkflowTraceResultUtil.getActionsThatReceived(
                                trace, HandshakeMessageType.SERVER_HELLO)
                        .get(0));
        assertEquals(
                serverHelloRAction,
                WorkflowTraceResultUtil.getActionsThatReceived(trace, ProtocolMessageType.HANDSHAKE)
                        .get(0));

        DummyReceivingAction alertRAction = new DummyReceivingAction(new AlertMessage());
        trace.addTlsAction(alertRAction);

        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(trace, ProtocolMessageType.HANDSHAKE)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(
                                trace, HandshakeMessageType.SERVER_HELLO)
                        .size());
        assertEquals(
                1,
                WorkflowTraceResultUtil.getActionsThatReceived(trace, ProtocolMessageType.ALERT)
                        .size());
        assertEquals(
                alertRAction,
                WorkflowTraceResultUtil.getActionsThatReceived(trace, ProtocolMessageType.ALERT)
                        .get(0));
    }

    @Test
    public void testGetFirstActionThatReceived3() {
        trace.addTlsActions(
                new DummySendingAction(new FinishedMessage()),
                new DummyReceivingAction(new FinishedMessage()));
        assertTrue(
                WorkflowTraceResultUtil.getFirstActionThatReceived(
                                trace, HandshakeMessageType.FINISHED)
                        instanceof DummyReceivingAction);
    }

    @Test
    public void testGetFirstActionThatReceived2() {
        trace.addTlsActions(
                new DummyReceivingAction(new FinishedMessage()),
                new DummySendingAction(new FinishedMessage()));
        assertTrue(
                WorkflowTraceResultUtil.getFirstActionThatReceived(
                                trace, HandshakeMessageType.FINISHED)
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
                        trace, HandshakeMessageType.FINISHED));
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
                        trace, HandshakeMessageType.FINISHED));
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
