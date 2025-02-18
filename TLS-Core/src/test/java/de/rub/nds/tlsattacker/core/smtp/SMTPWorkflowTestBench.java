/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.smtp.command.*;
import de.rub.nds.tlsattacker.core.smtp.reply.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.security.Security;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.checkerframework.checker.units.qual.C;
import org.junit.jupiter.api.*;

/**
 * Tests not to be included in the actual repo. Its just very convenient to run code this way from
 * IntelliJ
 */
 @Disabled
public class SMTPWorkflowTestBench {

    public static final int PLAIN_PORT = 2525;
    public static final int IMPLICIT_TLS_PORT = 4465;
    private Config config;

    @BeforeAll
    public static void addSecurityProvider() {
        ProviderUtil.addBouncyCastleProvider();
    }
    @BeforeEach
    public void changeLoglevel() {
        Configurator.setAllLevels("de.rub.nds.tlsattacker", org.apache.logging.log4j.Level.ALL);
    }

    private void initializeConfig(int port, StackConfiguration stackConfiguration) {
        config = new Config();
        config.setDefaultClientConnection(new OutboundConnection(port, "localhost"));
        config.setDefaultLayerConfiguration(stackConfiguration);
        config.setKeylogFilePath("/tmp/keylogfile");
        config.setWriteKeylogFile(true);
    }

    public void runWorkflowTrace(WorkflowTrace trace) throws JAXBException, IOException {
        State state = new State(config, trace);

        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            System.out.println(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            System.out.println(ex);
        }
        String res = WorkflowTraceSerializer.write(state.getWorkflowTrace());
        System.out.println(res);
        assert state.getWorkflowTrace().executedAsPlanned();
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testPlainSmtpWorkFlow() throws IOException, JAXBException {
        initializeConfig(PLAIN_PORT, StackConfiguration.SMTP);
        WorkflowConfigurationFactory workflowConfigurationFactory =
                new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.SMTP, RunningModeType.CLIENT);

        runWorkflowTrace(trace);
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlowSMTPS() throws IOException, JAXBException {
        initializeConfig(IMPLICIT_TLS_PORT, StackConfiguration.SMTPS);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(
                        WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        trace.addTlsAction(new ReceiveAction(new SmtpInitialGreeting()));
        trace.addTlsAction(new SendAction(new SmtpEHLOCommand("seal.upb.de")));
        trace.addTlsAction(new ReceiveAction(new SmtpEHLOReply()));
        trace.addTlsAction(new SendAction(new SmtpEXPNCommand("list@mailing.de")));
        trace.addTlsAction(new ReceiveAction(new SmtpEXPNReply()));
        trace.addTlsAction(new SendAction(new SmtpVRFYCommand("doesnotexist@mail.de")));
        trace.addTlsAction(new ReceiveAction(new SmtpVRFYReply()));
        trace.addTlsAction(new SendAction(new SmtpMAILCommand()));
        trace.addTlsAction(new ReceiveAction(new SmtpMAILReply()));
        trace.addTlsAction(new SendAction(new SmtpRCPTCommand()));
        trace.addTlsAction(new ReceiveAction(new SmtpRCPTReply()));
        trace.addTlsAction(new SendAction(new SmtpDATACommand()));
        trace.addTlsAction(new ReceiveAction(new SmtpDATAReply()));
        trace.addTlsAction(new SendAction(new SmtpDATAContentCommand("Test", "123", "lets go")));
        trace.addTlsAction(new ReceiveAction(new SmtpDATAContentReply()));
        trace.addTlsAction(new SendAction(new SmtpQUITCommand()));
        trace.addTlsAction(new ReceiveAction(new SmtpQUITReply()));

        runWorkflowTrace(trace);
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlowSTARTTLS() throws IOException, JAXBException {
        initializeConfig(PLAIN_PORT, StackConfiguration.SMTP);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(
                        WorkflowTraceType.SMTP_STARTTLS, RunningModeType.CLIENT);

        runWorkflowTrace(trace);
    }
}
