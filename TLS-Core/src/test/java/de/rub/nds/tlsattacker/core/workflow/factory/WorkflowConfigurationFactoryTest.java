/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class WorkflowConfigurationFactoryTest {

    /**
     * Checks if the left and right WorkflowTrace contain the same amount and combination of
     * MessageActions and their respective Messages. The Messages are matched by their Class.
     */
    private static boolean workflowTracesEqual(WorkflowTrace left, WorkflowTrace right) {
        if (left.getMessageActions().size() != right.getMessageActions().size()
                || left.getReceivingActions().size() != right.getReceivingActions().size()
                || left.getSendingActions().size() != right.getSendingActions().size()) {
            return false;
        }
        for (int i = 0; i < left.getMessageActions().size(); i++) {
            final MessageAction leftMessageAction = left.getMessageActions().get(i);
            final MessageAction rightMessageAction = right.getMessageActions().get(i);

            if (left.getMessageActions().size() != right.getMessageActions().size()
                    || !left.getMessageActions()
                            .get(i)
                            .getClass()
                            .equals(right.getMessageActions().get(i).getClass())) {
                return false;
            }
            for (int j = 0; j < leftMessageAction.getMessages().size(); j++) {
                if (!leftMessageAction
                        .getMessages()
                        .get(j)
                        .getClass()
                        .equals(rightMessageAction.getMessages().get(j).getClass())) {
                    return false;
                }
            }
            if (leftMessageAction instanceof ReceivingAction) {
                if (!(rightMessageAction instanceof ReceivingAction)) {
                    return false;
                }
                final ReceiveAction leftReceiveAction = (ReceiveAction) leftMessageAction;
                final ReceiveAction rightReceiveAction = (ReceiveAction) rightMessageAction;
                if (leftReceiveAction.getExpectedMessages().size()
                        != rightReceiveAction.getExpectedMessages().size()) {
                    return false;
                }
                for (int j = 0; j < leftReceiveAction.getMessages().size(); j++) {
                    if (!leftReceiveAction
                            .getExpectedMessages()
                            .get(j)
                            .getClass()
                            .equals(rightReceiveAction.getExpectedMessages().get(j).getClass())) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private Config config;
    private WorkflowConfigurationFactory workflowConfigurationFactory;

    public WorkflowConfigurationFactoryTest() {}

    @BeforeEach
    public void setUp() {
        config = Config.createConfig();
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
    }

    /** Test of createWorkflowTrace method, of class WorkflowConfigurationFactory. */
    @Test
    @Disabled("To be fixed")
    public void testCreateWorkflowTrace() {
        RunningModeType mode = RunningModeType.CLIENT;
        final WorkflowTrace hello0 =
                workflowConfigurationFactory.createWorkflowTrace(WorkflowTraceType.HELLO, mode);
        final WorkflowTrace hello1 =
                workflowConfigurationFactory.createWorkflowTrace(WorkflowTraceType.HELLO, mode);

        assertTrue(workflowTracesEqual(hello0, hello1));

        final List<WorkflowTrace> list = new ArrayList<>(WorkflowTraceType.values().length);

        for (WorkflowTraceType workflowTraceType : WorkflowTraceType.values()) {
            if (workflowTraceType == WorkflowTraceType.SIMPLE_MITM_PROXY) {
                mode = RunningModeType.MITM;
            } else {
                mode = RunningModeType.CLIENT;
            }
            if (workflowTraceType == WorkflowTraceType.DYNAMIC_HELLO
                    && mode != RunningModeType.CLIENT) {
                continue;
            }
            WorkflowTrace newTrace =
                    workflowConfigurationFactory.createWorkflowTrace(workflowTraceType, mode);
            assertNotNull(newTrace.getMessageActions());
            assertFalse(newTrace.getMessageActions().isEmpty());
            for (MessageAction action : newTrace.getMessageActions()) {
                if (action instanceof ReceiveAction) {
                    assertNotNull(((ReceiveAction) action).getExpectedMessages());
                    assertFalse(((ReceiveAction) action).getExpectedMessages().isEmpty());
                } else {
                    assertNotNull(action.getMessages());
                    assertFalse(action.getMessages().isEmpty());
                }
            }
            for (WorkflowTrace trace : list) {
                if (workflowTracesEqual(trace, newTrace)) {
                    fail(
                            MessageFormat.format(
                                    "The WorkflowConfigurationFactory is expected to produce different WorkflowTraces "
                                            + "for each WorkflowTraceType but there is a duplicate pair: {0} {1}",
                                    trace, newTrace));
                }
            }
            list.add(newTrace);
        }
    }

    /** Test of createHelloWorkflow method, of class WorkflowConfigurationFactory. */
    @Test
    public void testCreateHelloWorkflow() {
        WorkflowTrace helloWorkflow;
        MessageAction firstAction;
        MessageAction messageAction1;
        MessageAction messageAction2;
        ReceiveAction lastAction;
        ClientHelloMessage clientHelloMessage;

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

        assertEquals(1, firstAction.getMessages().size());
        assertTrue(lastAction.getExpectedMessages().size() >= 1);

        assertEquals(
                firstAction.getMessages().get(0).getClass(),
                de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage.class);
        assertEquals(
                lastAction.getExpectedMessages().get(0).getClass(),
                de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage.class);

        // Variants Test: if (highestProtocolVersion == DTLS10)
        config.setHighestProtocolVersion(ProtocolVersion.DTLS10);
        config.setClientAuthentication(false);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        helloWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.HELLO, RunningModeType.CLIENT);

        firstAction = helloWorkflow.getMessageActions().get(0);
        clientHelloMessage = (ClientHelloMessage) firstAction.getMessages().get(0);

        assertTrue(helloWorkflow.getMessageActions().size() >= 4);
        assertNotNull(helloWorkflow.getMessageActions().get(1));
        assertNotNull(helloWorkflow.getMessageActions().get(2));
        messageAction1 = helloWorkflow.getMessageActions().get(1);
        messageAction2 = helloWorkflow.getMessageActions().get(2);

        assertEquals(ReceiveAction.class, messageAction1.getClass());
        assertEquals(
                HelloVerifyRequestMessage.class,
                ((ReceiveAction) messageAction1).getExpectedMessages().get(0).getClass());
        assertEquals(ClientHelloMessage.class, messageAction2.getMessages().get(0).getClass());

        // if (highestProtocolVersion != TLS13)
        lastAction = (ReceiveAction) helloWorkflow.getLastMessageAction();
        assertEquals(
                lastAction.getExpectedMessages().get(1).getClass(),
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
                lastAction.getMessages().get(lastAction.getMessages().size() - 1).getClass());

        // Variants
        // if(config.isClientAuthentication())
        config.setClientAuthentication(true);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        handshakeWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
        lastAction = handshakeWorkflow.getLastMessageAction();
        assertEquals(ChangeCipherSpecMessage.class, lastAction.getMessages().get(0).getClass());
        assertEquals(CertificateMessage.class, lastAction.getMessages().get(1).getClass());
        assertEquals(CertificateVerifyMessage.class, lastAction.getMessages().get(2).getClass());
        assertEquals(FinishedMessage.class, lastAction.getMessages().get(3).getClass());

        // ! TLS13 config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setHighestProtocolVersion(ProtocolVersion.DTLS10);
        config.setClientAuthentication(true);
        workflowConfigurationFactory = new WorkflowConfigurationFactory(config);
        handshakeWorkflow =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);

        assertTrue(handshakeWorkflow.getMessageActions().size() >= 6);

        messageAction4 = handshakeWorkflow.getMessageActions().get(4);

        assertEquals(CertificateMessage.class, messageAction4.getMessages().get(0).getClass());
        assertEquals(
                CertificateVerifyMessage.class,
                messageAction4
                        .getMessages()
                        .get(messageAction4.getMessages().size() - 3)
                        .getClass());
        assertEquals(
                ChangeCipherSpecMessage.class,
                messageAction4
                        .getMessages()
                        .get(messageAction4.getMessages().size() - 2)
                        .getClass());
        assertEquals(
                FinishedMessage.class,
                messageAction4
                        .getMessages()
                        .get(messageAction4.getMessages().size() - 1)
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

        assertEquals(ApplicationMessage.class, messageAction3.getMessages().get(0).getClass());

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
        assertEquals(
                ApplicationMessage.class,
                ((ReceiveAction) messageAction3).getExpectedMessages().get(0).getClass());
        assertEquals(ApplicationMessage.class, messageAction4.getMessages().get(0).getClass());
        assertEquals(HeartbeatMessage.class, messageAction4.getMessages().get(1).getClass());
        assertEquals(ReceiveAction.class, messageAction5.getClass());
        assertEquals(
                HeartbeatMessage.class,
                ((ReceiveAction) messageAction5).getExpectedMessages().get(0).getClass());
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
}
