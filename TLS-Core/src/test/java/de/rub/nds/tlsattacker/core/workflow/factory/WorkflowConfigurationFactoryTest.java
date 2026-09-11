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
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
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
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpSTARTTLSCommand;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpInitialGreeting;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpSTARTTLSReply;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.commons.lang3.NotImplementedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

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
    @Disabled("Text Action WorkflowConfigurationFactory not implemented")
    public void testAddStartTlsAction() {
        config.setStarttlsType(StarttlsType.FTP);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        assertEquals(
                GenericReceiveTextAction.class, workflowTrace.getTlsActions().get(0).getClass());
        assertEquals(SendTextAction.class, workflowTrace.getTlsActions().get(1).getClass());
        assertEquals(
                GenericReceiveTextAction.class, workflowTrace.getTlsActions().get(2).getClass());

        config.setStarttlsType(StarttlsType.IMAP);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        assertEquals(
                GenericReceiveTextAction.class, workflowTrace.getTlsActions().get(0).getClass());
        assertEquals(SendTextAction.class, workflowTrace.getTlsActions().get(1).getClass());
        assertEquals(
                GenericReceiveTextAction.class, workflowTrace.getTlsActions().get(2).getClass());

        config.setStarttlsType(StarttlsType.POP3);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        assertEquals(
                GenericReceiveTextAction.class, workflowTrace.getTlsActions().get(0).getClass());
        assertEquals(SendTextAction.class, workflowTrace.getTlsActions().get(1).getClass());
        assertEquals(
                GenericReceiveTextAction.class, workflowTrace.getTlsActions().get(2).getClass());

        config.setStarttlsType(StarttlsType.SMTP);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        assertEquals(
                GenericReceiveTextAction.class, workflowTrace.getTlsActions().get(0).getClass());
        assertEquals(SendTextAction.class, workflowTrace.getTlsActions().get(1).getClass());
        assertEquals(
                GenericReceiveTextAction.class, workflowTrace.getTlsActions().get(2).getClass());
        assertEquals(SendTextAction.class, workflowTrace.getTlsActions().get(3).getClass());
        assertEquals(
                GenericReceiveTextAction.class, workflowTrace.getTlsActions().get(4).getClass());
    }

    /**
     * FTP STARTTLS (RFC 4217) client upgrade: the trace must begin with the plaintext exchange
     * (receive greeting, send "AUTH TLS\r\n", receive reply), then an EnableLayerAction(RECORD,
     * MESSAGE) before any TLS messages.
     */
    @Test
    public void testAddStartTlsActionFtp() {
        config.setStarttlsType(StarttlsType.FTP);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        List<TlsAction> actions = workflowTrace.getTlsActions();
        assertEquals(ReceiveRegexTextAction.class, actions.get(0).getClass());
        assertEquals("^220 ", ((ReceiveRegexTextAction) actions.get(0)).getRegex());
        assertEquals(SendTextAction.class, actions.get(1).getClass());
        assertEquals("AUTH TLS\r\n", ((SendTextAction) actions.get(1)).getText());
        assertEquals(ReceiveRegexTextAction.class, actions.get(2).getClass());
        assertEquals("^234 ", ((ReceiveRegexTextAction) actions.get(2)).getRegex());
        assertEquals(EnableLayerAction.class, actions.get(3).getClass());
    }

    /**
     * With capability discovery enabled the FTP trace runs FEAT before AUTH TLS, so a server that
     * enforces the RFC 4217 command sequence can still be reached.
     */
    @Test
    public void testAddStartTlsActionFtpWithCapabilityDiscovery() {
        config.setStarttlsType(StarttlsType.FTP);
        config.setStarttlsUseCapabilityDiscovery(true);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        List<TlsAction> actions = workflowTrace.getTlsActions();
        assertEquals(ReceiveRegexTextAction.class, actions.get(0).getClass());
        assertEquals("^220 ", ((ReceiveRegexTextAction) actions.get(0)).getRegex());
        assertEquals(SendTextAction.class, actions.get(1).getClass());
        assertEquals("FEAT\r\n", ((SendTextAction) actions.get(1)).getText());
        assertEquals(ReceiveRegexTextAction.class, actions.get(2).getClass());
        assertEquals("^211 ", ((ReceiveRegexTextAction) actions.get(2)).getRegex());
        assertEquals(SendTextAction.class, actions.get(3).getClass());
        assertEquals("AUTH TLS\r\n", ((SendTextAction) actions.get(3)).getText());
        assertEquals(ReceiveRegexTextAction.class, actions.get(4).getClass());
        assertEquals("^234 ", ((ReceiveRegexTextAction) actions.get(4)).getRegex());
        assertEquals(EnableLayerAction.class, actions.get(5).getClass());
    }

    /**
     * Both replies of the discovery variant must abort on an error status, not only the upgrade.
     */
    @Test
    public void testCapabilityDiscoveryRepliesAbortOnErrorStatus() {
        config.setStarttlsType(StarttlsType.FTP);
        config.setStarttlsUseCapabilityDiscovery(true);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        List<TlsAction> actions = workflowTrace.getTlsActions();
        assertEquals("^[45]\\d\\d ", ((ReceiveRegexTextAction) actions.get(2)).getAbortRegex());
        assertEquals("^[45]\\d\\d ", ((ReceiveRegexTextAction) actions.get(4)).getAbortRegex());
    }

    /** The discovery exchange is off by default, so the minimal RFC 4217 flow is what FTP emits. */
    @Test
    public void testCapabilityDiscoveryIsDisabledByDefault() {
        config.setStarttlsType(StarttlsType.FTP);
        assertFalse(config.isStarttlsUseCapabilityDiscovery());
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        List<TlsAction> actions = workflowTrace.getTlsActions();
        assertEquals("^220 ", ((ReceiveRegexTextAction) actions.get(0)).getRegex());
        assertEquals("AUTH TLS\r\n", ((SendTextAction) actions.get(1)).getText());
        assertEquals("^234 ", ((ReceiveRegexTextAction) actions.get(2)).getRegex());
        assertEquals(EnableLayerAction.class, actions.get(3).getClass());
    }

    /**
     * An SSL2 hello workflow under -starttls FTP must use the plaintext FTP prefix, then enable the
     * SSL2 layer (an SSL2 stack has neither a record nor a message layer), and only then exchange
     * the SSL2 messages.
     */
    @Test
    public void testCreateSsl2HelloWorkflowWithFtpStarttls() {
        config.setStarttlsType(StarttlsType.FTP);
        config.setDefaultLayerConfiguration(StackConfiguration.GENERIC_OPPORTUNISTIC_SSL2);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.SSL2_HELLO, RunningModeType.CLIENT);

        List<TlsAction> actions = workflowTrace.getTlsActions();
        assertEquals(ReceiveRegexTextAction.class, actions.get(0).getClass());
        assertEquals("^220 ", ((ReceiveRegexTextAction) actions.get(0)).getRegex());
        assertEquals(SendTextAction.class, actions.get(1).getClass());
        assertEquals("AUTH TLS\r\n", ((SendTextAction) actions.get(1)).getText());
        assertEquals(ReceiveRegexTextAction.class, actions.get(2).getClass());
        assertEquals("^234 ", ((ReceiveRegexTextAction) actions.get(2)).getRegex());

        assertEquals(EnableLayerAction.class, actions.get(3).getClass());
        assertEquals(
                Set.of(ImplementedLayers.SSL2),
                Set.copyOf(((EnableLayerAction) actions.get(3)).getTargetedLayers()));

        assertMessage(MessageActionDirection.SENDING, actions.get(4), SSL2ClientHelloMessage.class);
        assertMessage(
                MessageActionDirection.RECEIVING, actions.get(5), SSL2ServerHelloMessage.class);
        assertEquals(6, actions.size());
    }

    /**
     * Without an SSL2 stack the STARTTLS prefix keeps enabling the record and message layers, so
     * regular TLS STARTTLS workflows are unaffected by the SSL2 special case.
     */
    @Test
    public void testStarttlsEnablesRecordAndMessageLayerForTlsStack() {
        config.setStarttlsType(StarttlsType.FTP);
        config.setDefaultLayerConfiguration(StackConfiguration.GENERIC_OPPORTUNISTIC_TLS);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        WorkflowTrace workflowTrace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);

        TlsAction enableAction = workflowTrace.getTlsActions().get(3);
        assertEquals(EnableLayerAction.class, enableAction.getClass());
        assertEquals(
                Set.of(ImplementedLayers.RECORD, ImplementedLayers.MESSAGE),
                Set.copyOf(((EnableLayerAction) enableAction).getTargetedLayers()));
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
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(cfg);
        WorkflowTrace tlsTrace =
                factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, runningMode);

        cfg.setStarttlsType(StarttlsType.NONE);
        factory = new WorkflowConfigurationFactory(cfg);
        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.SMTPS, runningMode);

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
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(cfg);
        WorkflowTrace tlsTrace =
                factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, runningMode);

        cfg.setStarttlsType(StarttlsType.SMTP);
        factory = new WorkflowConfigurationFactory(cfg);
        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.SMTPS, runningMode);
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
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(cfg);
        WorkflowTrace tlsTrace =
                factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, runningMode);

        cfg.setStarttlsType(StarttlsType.NONE);
        factory = new WorkflowConfigurationFactory(cfg);
        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.POP3S, runningMode);
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
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(cfg);
        WorkflowTrace tlsTrace =
                factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, runningMode);

        cfg.setStarttlsType(StarttlsType.POP3);
        factory = new WorkflowConfigurationFactory(cfg);
        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.POP3S, runningMode);
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

    /** The STARTTLS protocols whose server greets of its own accord once the handshake is done. */
    private static Stream<StarttlsType> unpromptedGreetingTypes() {
        return Arrays.stream(StarttlsType.values())
                .filter(StarttlsType::sendsUnpromptedPostHandshakeGreeting);
    }

    private WorkflowTrace createTrace(
            StarttlsType type, ProtocolVersion version, WorkflowTraceType traceType) {
        config.setStarttlsType(type);
        config.setHighestProtocolVersion(version);
        config.setDefaultSelectedProtocolVersion(version);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        return workflowConfigurationFactory.createWorkflowTrace(traceType, RunningModeType.CLIENT);
    }

    private TlsAction lastAction(WorkflowTrace trace) {
        return trace.getTlsActions().get(trace.getTlsActions().size() - 1);
    }

    /**
     * A server that greets unprompted does so right behind its Finished. The handshake trace takes
     * the greeting in the receive that takes the server's ChangeCipherSpec and Finished rather than
     * trailing it, so callers that drop the last action to undo that receive drop the greeting
     * along with it.
     */
    @ParameterizedTest(allowZeroInvocations = true)
    @MethodSource("unpromptedGreetingTypes")
    public void testHandshakeMergesUnpromptedGreetingIntoServerFinishedReceive(StarttlsType type) {
        WorkflowTrace trace = createTrace(type, ProtocolVersion.TLS12, WorkflowTraceType.HANDSHAKE);

        TlsAction last = lastAction(trace);
        assertEquals(ReceiveAction.class, last.getClass());
        List<ProtocolMessage> expected = extractMessages((MessageAction) last);
        assertEquals(3, expected.size());
        assertEquals(ChangeCipherSpecMessage.class, expected.get(0).getClass());
        assertEquals(FinishedMessage.class, expected.get(1).getClass());
        assertEquals(ApplicationMessage.class, expected.get(2).getClass());
    }

    /**
     * The upgrade completes again on the resumed connection, so the greeting is sent again and has
     * to be read there as well. It follows the client's Finished, so it needs a receive of its own.
     * The abbreviated handshake is TLS 1.2, where the server cannot send the greeting any sooner,
     * so the receive has to find it and must not be allowed to come up empty.
     */
    @ParameterizedTest(allowZeroInvocations = true)
    @MethodSource("unpromptedGreetingTypes")
    public void testResumptionExpectsUnpromptedGreeting(StarttlsType type) {
        WorkflowTrace trace =
                createTrace(type, ProtocolVersion.TLS12, WorkflowTraceType.RESUMPTION);

        TlsAction last = lastAction(trace);
        assertEquals(ReceiveAction.class, last.getClass());
        List<ProtocolMessage> expected = extractMessages((MessageAction) last);
        assertEquals(1, expected.size());
        assertEquals(ApplicationMessage.class, expected.get(0).getClass());
        assertFalse(last.getActionOptions().contains(ActionOption.MAY_FAIL));
    }

    /**
     * In TLS 1.3 the server holds its application keys once it has sent its Finished, so it may
     * greet right behind it before the client's Finished. The receive of the server's flight
     * tolerates the greeting without waiting for it, and the trailing receive after the client's
     * Finished may then come up empty.
     */
    @ParameterizedTest(allowZeroInvocations = true)
    @MethodSource("unpromptedGreetingTypes")
    public void testHandshakeTls13ToleratesGreetingWithServerFinished(StarttlsType type) {
        WorkflowTrace trace = createTrace(type, ProtocolVersion.TLS13, WorkflowTraceType.HANDSHAKE);

        List<TlsAction> actions = trace.getTlsActions();
        TlsAction serverFlight = actions.get(actions.size() - 3);
        assertEquals(ReceiveAction.class, serverFlight.getClass());
        List<ProtocolMessage> expected = extractMessages((MessageAction) serverFlight);
        ProtocolMessage greeting = expected.get(expected.size() - 1);
        assertEquals(ApplicationMessage.class, greeting.getClass());
        assertFalse(greeting.isRequired());
        assertEquals(FinishedMessage.class, expected.get(expected.size() - 2).getClass());

        TlsAction clientFinished = actions.get(actions.size() - 2);
        assertEquals(SendAction.class, clientFinished.getClass());

        TlsAction last = lastAction(trace);
        assertEquals(ReceiveAction.class, last.getClass());
        List<ProtocolMessage> trailing = extractMessages((MessageAction) last);
        assertEquals(1, trailing.size());
        assertEquals(ApplicationMessage.class, trailing.get(0).getClass());
        assertTrue(last.getActionOptions().contains(ActionOption.MAY_FAIL));
    }

    /**
     * The greeting follows the server's Finished, often in the same segment. Reading till the
     * greeting takes the Finished along and ends at the same point whether or not the two arrive
     * together. A trailing receive for the greeting would wait out the timeout whenever the receive
     * before it had already taken the greeting with the Finished.
     */
    @ParameterizedTest(allowZeroInvocations = true)
    @MethodSource("unpromptedGreetingTypes")
    public void testDynamicHandshakeReadsTillUnpromptedGreeting(StarttlsType type) {
        WorkflowTrace trace =
                createTrace(type, ProtocolVersion.TLS12, WorkflowTraceType.DYNAMIC_HANDSHAKE);

        List<TlsAction> actions = trace.getTlsActions();
        TlsAction last = lastAction(trace);
        assertEquals(ReceiveTillAction.class, last.getClass());
        assertEquals(
                ApplicationMessage.class,
                ((ReceiveTillAction) last).getWaitTillMessage().getClass());
        TlsAction clientFinished = actions.get(actions.size() - 2);
        assertEquals(SendAction.class, clientFinished.getClass());
        List<ProtocolMessage> sent = extractMessages((MessageAction) clientFinished);
        assertEquals(FinishedMessage.class, sent.get(sent.size() - 1).getClass());
    }

    /**
     * In TLS 1.3 the client's Finished ends the handshake, so the greeting can only arrive after
     * the trace's last receive and gets a receive of its own, which may find nothing.
     */
    @ParameterizedTest(allowZeroInvocations = true)
    @MethodSource("unpromptedGreetingTypes")
    public void testDynamicHandshakeTls13AppendsUnpromptedGreeting(StarttlsType type) {
        WorkflowTrace trace =
                createTrace(type, ProtocolVersion.TLS13, WorkflowTraceType.DYNAMIC_HANDSHAKE);

        TlsAction last = lastAction(trace);
        assertEquals(ReceiveAction.class, last.getClass());
        List<ProtocolMessage> expected = extractMessages((MessageAction) last);
        assertEquals(1, expected.size());
        assertEquals(ApplicationMessage.class, expected.get(0).getClass());
        assertTrue(last.getActionOptions().contains(ActionOption.MAY_FAIL));
    }

    /**
     * The hello workflows stop before the upgrade has finished, so the greeting has not been sent
     * by the time they end. Adding a receive for it there would wait for data that cannot arrive.
     */
    @ParameterizedTest(allowZeroInvocations = true)
    @MethodSource("unpromptedGreetingTypes")
    public void testHelloWorkflowExpectsNoUnpromptedGreeting(StarttlsType type) {
        WorkflowTrace trace =
                createTrace(type, ProtocolVersion.TLS12, WorkflowTraceType.DYNAMIC_HELLO);

        assertNotEquals(ReceiveAction.class, lastAction(trace).getClass());
    }

    /**
     * FTP answers the upgrade and then waits, so its traces have to end where they always did. Only
     * the protocols that greet unprompted state a greeting.
     */
    @Test
    public void testFtpHandshakeLeavesServerFinishedReceiveAlone() {
        WorkflowTrace trace =
                createTrace(StarttlsType.FTP, ProtocolVersion.TLS12, WorkflowTraceType.HANDSHAKE);

        TlsAction last = lastAction(trace);
        assertEquals(ReceiveAction.class, last.getClass());
        List<ProtocolMessage> expected = extractMessages((MessageAction) last);
        assertEquals(2, expected.size());
        assertEquals(ChangeCipherSpecMessage.class, expected.get(0).getClass());
        assertEquals(FinishedMessage.class, expected.get(1).getClass());
    }

    @Test
    public void testFtpHandshakeTls13LeavesServerFlightReceiveAlone() {
        WorkflowTrace trace =
                createTrace(StarttlsType.FTP, ProtocolVersion.TLS13, WorkflowTraceType.HANDSHAKE);

        List<TlsAction> actions = trace.getTlsActions();
        TlsAction serverFlight = actions.get(actions.size() - 2);
        assertEquals(ReceiveAction.class, serverFlight.getClass());
        List<ProtocolMessage> expected = extractMessages((MessageAction) serverFlight);
        assertEquals(FinishedMessage.class, expected.get(expected.size() - 1).getClass());
        assertEquals(SendAction.class, lastAction(trace).getClass());
    }

    @Test
    public void testFtpResumptionExpectsNoGreeting() {
        WorkflowTrace trace =
                createTrace(StarttlsType.FTP, ProtocolVersion.TLS12, WorkflowTraceType.RESUMPTION);

        List<ProtocolMessage> expected = extractMessages((MessageAction) lastAction(trace));
        assertEquals(2, expected.size());
        assertEquals(ChangeCipherSpecMessage.class, expected.get(0).getClass());
        assertEquals(FinishedMessage.class, expected.get(1).getClass());
    }

    @Test
    public void testFtpDynamicHandshakeReadsTillServerFinished() {
        WorkflowTrace trace =
                createTrace(
                        StarttlsType.FTP,
                        ProtocolVersion.TLS12,
                        WorkflowTraceType.DYNAMIC_HANDSHAKE);

        TlsAction last = lastAction(trace);
        assertEquals(ReceiveTillAction.class, last.getClass());
        assertEquals(
                FinishedMessage.class, ((ReceiveTillAction) last).getWaitTillMessage().getClass());
    }

    /** A connection that never upgrades has no greeting to read, whatever the trace type. */
    @Test
    public void testHandshakeWithoutStartTlsExpectsNoGreeting() {
        WorkflowTrace trace =
                createTrace(
                        StarttlsType.NONE,
                        ProtocolVersion.TLS12,
                        WorkflowTraceType.DYNAMIC_HANDSHAKE);

        TlsAction last = lastAction(trace);
        assertEquals(ReceiveTillAction.class, last.getClass());
        assertEquals(
                FinishedMessage.class, ((ReceiveTillAction) last).getWaitTillMessage().getClass());
    }
}
