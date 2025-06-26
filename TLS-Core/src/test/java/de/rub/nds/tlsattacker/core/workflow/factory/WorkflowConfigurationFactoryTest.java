/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAsciiAction;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class WorkflowConfigurationFactoryTest {

    public List<ProtocolMessage> extractMessages(MessageAction action) {
        if (action instanceof SendAction) {
            return ((SendAction) action).getConfiguredMessages();
        } else if (action instanceof ReceiveAction) {
            return ((ReceiveAction) action).getExpectedMessages();
        } else {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }

    private Config config;
    private WorkflowConfigurationFactory workflowConfigurationFactory;

    public WorkflowConfigurationFactoryTest() {}

    @BeforeEach
    public void setUp() {
        config = new Config();
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
    }

    /** Test of createHelloWorkflow method, of class WorkflowConfigurationFactory. */
    @Test
    public void testCreateHelloWorkflow() {
        WorkflowTrace helloWorkflow;
        MessageAction firstAction;
        MessageAction messageAction1;
        MessageAction messageAction2;
        ReceiveAction lastAction;

        // Invariants Test: We will always obtain a WorkflowTrace containing at
        // least two TLS-Actions with exactly one message for the first
        // TLS-Action and at least one message for the last TLS-Action, which
        // would be the basic Client/Server-Hello:
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        helloWorkflow =
                factory.createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.CLIENT);

        assertTrue(helloWorkflow.getMessageActions().size() >= 2);

        firstAction = helloWorkflow.getMessageActions().get(0);

        assertEquals(ReceiveAction.class, helloWorkflow.getLastMessageAction().getClass());

        lastAction = (ReceiveAction) helloWorkflow.getLastMessageAction();

        assertEquals(1, extractMessages(firstAction).size());
        assertTrue(lastAction.getExpectedMessages().size() >= 1);

        assertEquals(
                extractMessages(firstAction).get(0).getClass(),
                de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage.class);
        assertEquals(
                extractMessages(lastAction).get(0).getClass(),
                de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage.class);

        // Variants Test: if (highestProtocolVersion == DTLS10)
        config.setHighestProtocolVersion(ProtocolVersion.DTLS10);
        config.setClientAuthentication(false);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        helloWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.HELLO, RunningModeType.CLIENT);

        firstAction = helloWorkflow.getMessageActions().get(0);
        assertTrue(helloWorkflow.getMessageActions().size() >= 4);
        assertNotNull(helloWorkflow.getMessageActions().get(1));
        assertNotNull(helloWorkflow.getMessageActions().get(2));
        messageAction1 = helloWorkflow.getMessageActions().get(1);
        messageAction2 = helloWorkflow.getMessageActions().get(2);

        assertEquals(ReceiveAction.class, messageAction1.getClass());
        assertEquals(
                HelloVerifyRequestMessage.class, extractMessages(messageAction1).get(0).getClass());
        assertEquals(ClientHelloMessage.class, extractMessages(messageAction2).get(0).getClass());

        // if (highestProtocolVersion != TLS13)
        lastAction = (ReceiveAction) helloWorkflow.getLastMessageAction();
        assertEquals(
                extractMessages(lastAction).get(1).getClass(),
                de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage.class);

        // if config.getDefaultSelectedCipherSuite().isEphemeral()
        config.setHighestProtocolVersion(ProtocolVersion.DTLS10);
        config.setClientAuthentication(true);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        helloWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.HELLO, RunningModeType.CLIENT);

        lastAction = (ReceiveAction) helloWorkflow.getLastMessageAction();
        assertNotNull(lastAction.getExpectedMessages().get(2));
        assertEquals(
                lastAction.getExpectedMessages().get(3).getClass(),
                de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage.class);
    }

    /** Test of createHandshakeWorkflow method, of class WorkflowConfigurationFactory. */
    @Test()
    public void testCreateHandshakeWorkflow() {
        WorkflowTrace handshakeWorkflow;
        MessageAction lastAction;
        MessageAction messageAction4;
        ReceiveAction receiveAction;

        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setClientAuthentication(false);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        handshakeWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);

        // Invariants
        assertTrue(handshakeWorkflow.getMessageActions().size() >= 3);
        assertNotNull(handshakeWorkflow.getLastMessageAction());

        lastAction = handshakeWorkflow.getLastMessageAction();

        assertEquals(
                FinishedMessage.class,
                extractMessages(lastAction).get(extractMessages(lastAction).size() - 1).getClass());

        // Variants
        // if(config.isClientAuthentication())
        config.setClientAuthentication(true);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        handshakeWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
        lastAction = handshakeWorkflow.getLastMessageAction();
        assertEquals(ChangeCipherSpecMessage.class, extractMessages(lastAction).get(0).getClass());
        assertEquals(CertificateMessage.class, extractMessages(lastAction).get(1).getClass());
        assertEquals(CertificateVerifyMessage.class, extractMessages(lastAction).get(2).getClass());
        assertEquals(FinishedMessage.class, extractMessages(lastAction).get(3).getClass());

        // ! TLS13 config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setHighestProtocolVersion(ProtocolVersion.DTLS10);
        config.setClientAuthentication(true);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        handshakeWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);

        assertTrue(handshakeWorkflow.getMessageActions().size() >= 6);

        messageAction4 = handshakeWorkflow.getMessageActions().get(4);

        assertEquals(CertificateMessage.class, extractMessages(messageAction4).get(0).getClass());
        assertEquals(
                CertificateVerifyMessage.class,
                extractMessages(messageAction4)
                        .get(extractMessages(messageAction4).size() - 3)
                        .getClass());
        assertEquals(
                ChangeCipherSpecMessage.class,
                extractMessages(messageAction4)
                        .get(extractMessages(messageAction4).size() - 2)
                        .getClass());
        assertEquals(
                FinishedMessage.class,
                extractMessages(messageAction4)
                        .get(extractMessages(messageAction4).size() - 1)
                        .getClass());

        receiveAction = (ReceiveAction) handshakeWorkflow.getLastMessageAction();

        assertEquals(
                ChangeCipherSpecMessage.class,
                receiveAction.getExpectedMessages().get(0).getClass());
        assertEquals(FinishedMessage.class, receiveAction.getExpectedMessages().get(1).getClass());
    }

    /** Test of createFullWorkflow method, of class WorkflowConfigurationFactory. */
    @Test
    public void testCreateFullWorkflow() {
        MessageAction messageAction3;
        MessageAction messageAction4;
        MessageAction messageAction5;

        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setClientAuthentication(true);
        config.setServerSendsApplicationData(false);
        config.setAddHeartbeatExtension(false);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace fullWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.FULL, RunningModeType.CLIENT);

        // Invariants
        assertTrue(fullWorkflow.getMessageActions().size() >= 4);

        messageAction3 = fullWorkflow.getMessageActions().get(3);

        assertEquals(ApplicationMessage.class, extractMessages(messageAction3).get(0).getClass());

        // Invariants
        config.setServerSendsApplicationData(true);
        config.setAddHeartbeatExtension(true);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        fullWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.FULL, RunningModeType.CLIENT);

        assertTrue(fullWorkflow.getMessageActions().size() >= 6);

        messageAction3 = fullWorkflow.getMessageActions().get(3);
        messageAction4 = fullWorkflow.getMessageActions().get(4);
        messageAction5 = fullWorkflow.getMessageActions().get(5);

        assertEquals(ReceiveAction.class, messageAction3.getClass());
        assertEquals(ApplicationMessage.class, extractMessages(messageAction3).get(0).getClass());
        assertEquals(ApplicationMessage.class, extractMessages(messageAction4).get(0).getClass());
        assertEquals(HeartbeatMessage.class, extractMessages(messageAction4).get(1).getClass());
        assertEquals(ReceiveAction.class, messageAction5.getClass());
        assertEquals(HeartbeatMessage.class, extractMessages(messageAction5).get(0).getClass());
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testNoExceptions() {
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            for (ProtocolVersion version : ProtocolVersion.values()) {
                for (WorkflowTraceType type : WorkflowTraceType.values()) {
                    // TODO: reimplement when adding https
                    if (type == WorkflowTraceType.HTTPS
                            || type == WorkflowTraceType.DYNAMIC_HTTPS) {
                        continue;
                    }
                    try {
                        config.setDefaultSelectedCipherSuite(suite);
                        config.setSupportedVersions(version);
                        config.setHighestProtocolVersion(version);
                        config.setDefaultServerSupportedCipherSuites(suite);
                        config.setDefaultClientSupportedCipherSuites(suite);
                        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
                        config.setDefaultRunningMode(RunningModeType.CLIENT);
                        workflowConfigurationFactory.createWorkflowTrace(
                                type, RunningModeType.CLIENT);
                        if (type == WorkflowTraceType.DYNAMIC_HELLO) {
                            continue;
                        }
                        config.setDefaultRunningMode(RunningModeType.SERVER);
                        workflowConfigurationFactory.createWorkflowTrace(
                                type, RunningModeType.SERVER);
                        config.setDefaultRunningMode(RunningModeType.MITM);
                        workflowConfigurationFactory.createWorkflowTrace(
                                type, RunningModeType.MITM);
                    } catch (ConfigurationException E) {
                        // Those are ok
                    }
                }
            }
        }
    }

    /** Test of addStartTlsAction method, of class WorkflowConfigurationFactory. */
    @Test
    @Disabled("ASCII Action WorkfloConfigurationFactory not implemented")
    public void testAddStartTlsAction() {
        config.setStarttlsType(StarttlsType.FTP);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        assertEquals(
                GenericReceiveAsciiAction.class, workflowTrace.getTlsActions().get(0).getClass());
        assertEquals(SendAsciiAction.class, workflowTrace.getTlsActions().get(1).getClass());
        assertEquals(
                GenericReceiveAsciiAction.class, workflowTrace.getTlsActions().get(2).getClass());

        config.setStarttlsType(StarttlsType.IMAP);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        assertEquals(
                GenericReceiveAsciiAction.class, workflowTrace.getTlsActions().get(0).getClass());
        assertEquals(SendAsciiAction.class, workflowTrace.getTlsActions().get(1).getClass());
        assertEquals(
                GenericReceiveAsciiAction.class, workflowTrace.getTlsActions().get(2).getClass());

        config.setStarttlsType(StarttlsType.POP3);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        assertEquals(
                GenericReceiveAsciiAction.class, workflowTrace.getTlsActions().get(0).getClass());
        assertEquals(SendAsciiAction.class, workflowTrace.getTlsActions().get(1).getClass());
        assertEquals(
                GenericReceiveAsciiAction.class, workflowTrace.getTlsActions().get(2).getClass());

        config.setStarttlsType(StarttlsType.SMTP);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        assertEquals(
                GenericReceiveAsciiAction.class, workflowTrace.getTlsActions().get(0).getClass());
        assertEquals(SendAsciiAction.class, workflowTrace.getTlsActions().get(1).getClass());
        assertEquals(
                GenericReceiveAsciiAction.class, workflowTrace.getTlsActions().get(2).getClass());
        assertEquals(SendAsciiAction.class, workflowTrace.getTlsActions().get(3).getClass());
        assertEquals(
                GenericReceiveAsciiAction.class, workflowTrace.getTlsActions().get(4).getClass());
    }

    /** Test that dynamic handshake workflow includes proper connection termination */
    @Test
    public void testDynamicHandshakeWorkflowIncludesCloseNotify() {
        // Test for TLS 1.2
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);

        // Find the close_notify send action (should be second to last)
        MessageAction secondToLastAction =
                trace.getMessageActions().get(trace.getMessageActions().size() - 2);
        assertTrue(secondToLastAction instanceof SendAction);
        SendAction closeNotifySendAction = (SendAction) secondToLastAction;
        assertEquals(1, closeNotifySendAction.getConfiguredMessages().size());
        ProtocolMessage closeNotifyMessage = closeNotifySendAction.getConfiguredMessages().get(0);
        assertTrue(closeNotifyMessage instanceof AlertMessage);
        AlertMessage closeNotifyAlert = (AlertMessage) closeNotifyMessage;
        assertEquals(AlertLevel.WARNING.getValue(), closeNotifyAlert.getLevel().getValue());
        assertEquals(
                AlertDescription.CLOSE_NOTIFY.getValue(),
                closeNotifyAlert.getDescription().getValue());

        // Find the close_notify receive action (should be last)
        MessageAction lastAction = trace.getLastMessageAction();
        assertTrue(lastAction instanceof ReceiveTillAction);
        ReceiveTillAction closeNotifyReceiveAction = (ReceiveTillAction) lastAction;
        ProtocolMessage expectedCloseNotify = closeNotifyReceiveAction.getWaitTillMessage();
        assertNotNull(expectedCloseNotify);
        assertTrue(expectedCloseNotify instanceof AlertMessage);
        AlertMessage expectedCloseNotifyAlert = (AlertMessage) expectedCloseNotify;
        assertEquals(AlertLevel.WARNING.getValue(), expectedCloseNotifyAlert.getLevel().getValue());
        assertEquals(
                AlertDescription.CLOSE_NOTIFY.getValue(),
                expectedCloseNotifyAlert.getDescription().getValue());

        // Test for TLS 1.3
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        trace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);

        // Find the close_notify send action (should be second to last)
        secondToLastAction = trace.getMessageActions().get(trace.getMessageActions().size() - 2);
        assertTrue(secondToLastAction instanceof SendAction);
        closeNotifySendAction = (SendAction) secondToLastAction;
        assertEquals(1, closeNotifySendAction.getConfiguredMessages().size());
        closeNotifyMessage = closeNotifySendAction.getConfiguredMessages().get(0);
        assertTrue(closeNotifyMessage instanceof AlertMessage);
        closeNotifyAlert = (AlertMessage) closeNotifyMessage;
        assertEquals(AlertLevel.WARNING.getValue(), closeNotifyAlert.getLevel().getValue());
        assertEquals(
                AlertDescription.CLOSE_NOTIFY.getValue(),
                closeNotifyAlert.getDescription().getValue());

        // Find the close_notify receive action (should be last)
        lastAction = trace.getLastMessageAction();
        assertTrue(lastAction instanceof ReceiveTillAction);
        closeNotifyReceiveAction = (ReceiveTillAction) lastAction;
        expectedCloseNotify = closeNotifyReceiveAction.getWaitTillMessage();
        assertNotNull(expectedCloseNotify);
        assertTrue(expectedCloseNotify instanceof AlertMessage);
        expectedCloseNotifyAlert = (AlertMessage) expectedCloseNotify;
        assertEquals(AlertLevel.WARNING.getValue(), expectedCloseNotifyAlert.getLevel().getValue());
        assertEquals(
                AlertDescription.CLOSE_NOTIFY.getValue(),
                expectedCloseNotifyAlert.getDescription().getValue());
    }
}
