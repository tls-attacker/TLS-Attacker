/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

import static de.rub.nds.tlsattacker.core.workflow.action.MessageAction.MessageActionDirection;
import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3NOOPCommand;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3STLSCommand;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3InitialGreeting;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3NOOPReply;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3STLSReply;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpSTARTTLSCommand;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpInitialGreeting;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpSTARTTLSReply;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.util.List;
import org.apache.commons.lang3.NotImplementedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

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

    private static void assertMessage(
            MessageActionDirection expectedDirection,
            TlsAction action,
            Class<? extends DataContainer>... expectedMessageClasses) {
        assertInstanceOf(MessageAction.class, action, "Expected a MessageAction");
        MessageActionDirection actualDirection = ((MessageAction) action).getMessageDirection();

        assertEquals(
                expectedDirection,
                actualDirection,
                () -> {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Message action direction does not match\n");
                    sb.append("Expected direction: ").append(expectedDirection).append("\n");
                    sb.append("Expected Messages:\n");
                    for (Class<?> msgClass : expectedMessageClasses) {
                        sb.append(" - ").append(msgClass.getSimpleName()).append("\n");
                    }
                    sb.append("Actual action:\n");
                    sb.append(action.toString());
                    return sb.toString();
                });

        List<List<DataContainer>> containerLists;
        if (actualDirection == MessageActionDirection.SENDING) {
            containerLists = ((SendAction) action).getConfiguredDataContainerLists();
        } else {
            containerLists = ((ReceiveAction) action).getExpectedDataContainerLists();
        }

        List<DataContainer> actualMessages = null;
        for (List<DataContainer> msgList : containerLists) {
            if (msgList.size() > 0) {
                if (actualMessages != null) {
                    throw new NotImplementedException(
                            "Bad Test/Assertion: This assertion can only handle a single layer to be configured in a send/receive action.");
                }
                actualMessages = msgList;
            }
        }

        assertEquals(expectedMessageClasses.length, actualMessages.size());
        for (int i = 0; i < expectedMessageClasses.length; i++) {
            assertEquals(
                    expectedMessageClasses[i],
                    actualMessages.get(i).getClass(),
                    "Message " + i + " does not match");
        }
    }

    @ParameterizedTest
    @EnumSource(
            value = RunningModeType.class,
            names = {"CLIENT", "SERVER"})
    void testCreateSmtpsClientWorkflow(RunningModeType runningMode) {
        MessageActionDirection SERVER_MSG_DIRECTION =
                (runningMode == RunningModeType.CLIENT)
                        ? MessageActionDirection.RECEIVING
                        : MessageActionDirection.SENDING;
        MessageActionDirection CLIENT_MSG_DIRECTION =
                (runningMode == RunningModeType.CLIENT)
                        ? MessageActionDirection.SENDING
                        : MessageActionDirection.RECEIVING;

        Config cfg = new Config();
        cfg.setStarttlsType(StarttlsType.NONE);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(cfg);

        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.SMTPS, runningMode);
        WorkflowTrace tlsTrace =
                factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, runningMode);
        assertNotNull(trace);
        int index = 0;

        // TLS handshake
        for (int n = 0; n < tlsTrace.getTlsActions().size(); n++) {
            assertEquals(tlsTrace.getTlsActions().get(n), trace.getTlsActions().get(index++));
        }
        // server: SMTP greeting
        assertMessage(
                SERVER_MSG_DIRECTION,
                trace.getTlsActions().get(index++),
                SmtpInitialGreeting.class);
        // client: EHLO
        assertMessage(
                CLIENT_MSG_DIRECTION, trace.getTlsActions().get(index++), SmtpEHLOCommand.class);
        // server: 250 response
        assertMessage(
                SERVER_MSG_DIRECTION, trace.getTlsActions().get(index++), SmtpEHLOReply.class);

        // done
        assertEquals(index, trace.getTlsActions().size());
    }

    @ParameterizedTest
    @EnumSource(
            value = RunningModeType.class,
            names = {"CLIENT", "SERVER"})
    void testCreateSmtpStarttlsClientWorkflow(RunningModeType runningMode) {
        MessageActionDirection SERVER_MSG_DIRECTION =
                (runningMode == RunningModeType.CLIENT)
                        ? MessageActionDirection.RECEIVING
                        : MessageActionDirection.SENDING;
        MessageActionDirection CLIENT_MSG_DIRECTION =
                (runningMode == RunningModeType.CLIENT)
                        ? MessageActionDirection.SENDING
                        : MessageActionDirection.RECEIVING;

        Config cfg = new Config();
        cfg.setStarttlsType(StarttlsType.SMTP);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(cfg);

        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.SMTPS, runningMode);
        WorkflowTrace tlsTrace =
                factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, runningMode);
        assertNotNull(trace);
        int index = 0;

        // server: SMTP greeting
        assertMessage(
                SERVER_MSG_DIRECTION,
                trace.getTlsActions().get(index++),
                SmtpInitialGreeting.class);
        // client: EHLO
        assertMessage(
                CLIENT_MSG_DIRECTION, trace.getTlsActions().get(index++), SmtpEHLOCommand.class);
        // server: 250 response
        assertMessage(
                SERVER_MSG_DIRECTION, trace.getTlsActions().get(index++), SmtpEHLOReply.class);
        // client: STARTTLS command
        assertMessage(
                CLIENT_MSG_DIRECTION,
                trace.getTlsActions().get(index++),
                SmtpSTARTTLSCommand.class);
        // server: 220 response
        assertMessage(
                SERVER_MSG_DIRECTION, trace.getTlsActions().get(index++), SmtpSTARTTLSReply.class);

        // enable TLS layers
        assertEquals(trace.getTlsActions().get(index++).getClass(), EnableLayerAction.class);
        // TLS handshake
        for (int n = 0; n < tlsTrace.getTlsActions().size(); n++) {
            assertEquals(tlsTrace.getTlsActions().get(n), trace.getTlsActions().get(index++));
        }
        // client: EHLO
        assertMessage(
                CLIENT_MSG_DIRECTION, trace.getTlsActions().get(index++), SmtpEHLOCommand.class);
        // server: 250 response
        assertMessage(
                SERVER_MSG_DIRECTION, trace.getTlsActions().get(index++), SmtpEHLOReply.class);

        // done
        assertEquals(index, trace.getTlsActions().size());
    }

    @ParameterizedTest
    @EnumSource(
            value = RunningModeType.class,
            names = {"CLIENT", "SERVER"})
    void testCreatePop3sClientWorkflow(RunningModeType runningMode) {
        MessageActionDirection SERVER_MSG_DIRECTION =
                (runningMode == RunningModeType.CLIENT)
                        ? MessageActionDirection.RECEIVING
                        : MessageActionDirection.SENDING;
        MessageActionDirection CLIENT_MSG_DIRECTION =
                (runningMode == RunningModeType.CLIENT)
                        ? MessageActionDirection.SENDING
                        : MessageActionDirection.RECEIVING;

        Config cfg = new Config();
        cfg.setStarttlsType(StarttlsType.NONE);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(cfg);

        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.POP3S, runningMode);
        WorkflowTrace tlsTrace =
                factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, runningMode);
        assertNotNull(trace);
        int index = 0;

        // TLS handshake
        for (int n = 0; n < tlsTrace.getTlsActions().size(); n++) {
            assertEquals(tlsTrace.getTlsActions().get(n), trace.getTlsActions().get(index++));
        }

        // server: POP3 greeting
        assertMessage(
                SERVER_MSG_DIRECTION,
                trace.getTlsActions().get(index++),
                Pop3InitialGreeting.class);
        // client: NOOP
        assertMessage(
                CLIENT_MSG_DIRECTION, trace.getTlsActions().get(index++), Pop3NOOPCommand.class);
        // server: +OK response
        assertMessage(
                SERVER_MSG_DIRECTION, trace.getTlsActions().get(index++), Pop3NOOPReply.class);

        // done
        assertEquals(index, trace.getTlsActions().size());
    }

    @ParameterizedTest
    @EnumSource(
            value = RunningModeType.class,
            names = {"CLIENT", "SERVER"})
    void testCreatePop3StarttlsClientWorkflow(RunningModeType runningMode) {
        MessageActionDirection SERVER_MSG_DIRECTION =
                (runningMode == RunningModeType.CLIENT)
                        ? MessageActionDirection.RECEIVING
                        : MessageActionDirection.SENDING;
        MessageActionDirection CLIENT_MSG_DIRECTION =
                (runningMode == RunningModeType.CLIENT)
                        ? MessageActionDirection.SENDING
                        : MessageActionDirection.RECEIVING;

        Config cfg = new Config();
        cfg.setStarttlsType(StarttlsType.POP3);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(cfg);

        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.POP3S, runningMode);
        WorkflowTrace tlsTrace =
                factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, runningMode);
        assertNotNull(trace);
        int index = 0;

        // server: POP3 greeting
        assertMessage(
                SERVER_MSG_DIRECTION,
                trace.getTlsActions().get(index++),
                Pop3InitialGreeting.class);
        // client: STLS command
        assertMessage(
                CLIENT_MSG_DIRECTION, trace.getTlsActions().get(index++), Pop3STLSCommand.class);
        // server: +OK response
        assertMessage(
                SERVER_MSG_DIRECTION, trace.getTlsActions().get(index++), Pop3STLSReply.class);

        // enable TLS layers
        assertEquals(trace.getTlsActions().get(index++).getClass(), EnableLayerAction.class);
        // TLS handshake
        for (int n = 0; n < tlsTrace.getTlsActions().size(); n++) {
            assertEquals(tlsTrace.getTlsActions().get(n), trace.getTlsActions().get(index++));
        }
        // client: NOOP
        assertMessage(
                CLIENT_MSG_DIRECTION, trace.getTlsActions().get(index++), Pop3NOOPCommand.class);
        // server: +OK response
        assertMessage(
                SERVER_MSG_DIRECTION, trace.getTlsActions().get(index++), Pop3NOOPReply.class);

        // done
        assertEquals(index, trace.getTlsActions().size());
    }
}
