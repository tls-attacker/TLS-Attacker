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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Tests not to be included in the actual repo. Its just very convenient to run code this way from
 * IntelliJ
 */
public class SMTPWorkflowTestBench {

    @BeforeEach
    public void changeLoglevel() {
        Configurator.setAllLevels("de.rub.nds.tlsattacker", org.apache.logging.log4j.Level.ALL);
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlow() throws IOException, JAXBException {
        Security.addProvider(new BouncyCastleProvider());
        Config config = Config.createConfig();
        config.setDefaultClientConnection(new OutboundConnection(2525, "localhost"));
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);

        WorkflowConfigurationFactory workflowConfigurationFactory =
                new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                workflowConfigurationFactory.createWorkflowTrace(
                        WorkflowTraceType.SMTP, RunningModeType.CLIENT);
        //        WorkflowTrace trace = new WorkflowTrace();
        //
        //        trace.addTlsAction(new ReceiveAction(new SmtpInitialGreeting()));
        //        trace.addTlsAction(new SendAction(new SmtpEHLOCommand("seal.upb.de")));
        //        trace.addTlsAction(new ReceiveAction(new SmtpEHLOReply()));
        //        trace.addTlsAction(new SendAction(new SmtpMAILCommand()));
        //        trace.addTlsAction(new ReceiveAction(new SmtpMAILReply()));
        //        trace.addTlsAction(new SendAction(new SmtpRCPTCommand()));
        //        trace.addTlsAction(new ReceiveAction(new SmtpRCPTReply()));
        //        trace.addTlsAction(new SendAction(new SmtpDATACommand()));
        //        trace.addTlsAction(new ReceiveAction(new SmtpDATAReply()));
        //        trace.addTlsAction(new SendAction(new SmtpDATAContentCommand("Test", "123", "lets
        // go")));
        //        trace.addTlsAction(new ReceiveAction(new SmtpDATAContentReply()));
        //        trace.addTlsAction(new SendAction(new SmtpQUITCommand()));
        //        trace.addTlsAction(new ReceiveAction(new SmtpQUITReply()));

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

        System.out.println(state.getWorkflowTrace().executedAsPlanned());
        String res = WorkflowTraceSerializer.write(state.getWorkflowTrace());
        System.out.println(res);
        assert (state.getWorkflowTrace().executedAsPlanned());
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlowSMTPS() throws IOException, JAXBException {
        Security.addProvider(new BouncyCastleProvider());
        Config config = Config.createConfig();
        config.setDefaultClientConnection(new OutboundConnection(4443, "localhost"));
        config.setDefaultLayerConfiguration(StackConfiguration.SMTPS);

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

        System.out.println(trace);
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

        System.out.println(state.getWorkflowTrace());
        System.out.println(state.getContext().getLayerStack().getHighestLayer().getLayerResult());
        assert state.getWorkflowTrace().executedAsPlanned();
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlowSTARTTLS() throws IOException, JAXBException {
        Security.addProvider(new BouncyCastleProvider());
        Config config = Config.createConfig();
        config.setKeylogFilePath("/tmp/keylog.log");
        config.setWriteKeylogFile(true);
        config.setDefaultClientConnection(new OutboundConnection(2525, "localhost"));
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(
                        WorkflowTraceType.SMTP_STARTTLS, RunningModeType.CLIENT);

        //        trace.addTlsAction(0, new ReceiveAction(new SmtpInitialGreeting()));
        //        trace.addTlsAction(1, new SendAction(new SmtpEHLOCommand("seal.upb.de")));
        //        trace.addTlsAction(2, new ReceiveAction(new SmtpEHLOReply()));
        //        trace.addTlsAction(3, new SendAction(new SmtpSTARTTLSCommand()));
        //        trace.addTlsAction(4, new ReceiveAction(new SmtpSTARTTLSReply()));
        //        trace.addTlsAction(5, new STARTTLSAction());
        //
        //        trace.addTlsAction(new ReceiveAction(new SmtpInitialGreeting()));
        //        trace.addTlsAction(new SendAction(new SmtpEHLOCommand("seal.upb.de")));
        //        trace.addTlsAction(new ReceiveAction(new SmtpEHLOReply()));
        //        //        trace.addTlsAction(new SendAction(new SmtpQUITCommand()));
        //        //        trace.addTlsAction(new ReceiveAction(new SmtpQUITReply()));
        //
        //        trace.addTlsAction(new STARTTLSAction());
        //
        //        //        trace.addTlsAction(new SendAction(new
        //        // SmtpEHLOCommand("commandinjection.seal.upb.de")));
        //        trace.addTlsAction(new SendAction(new SmtpNOOPCommand()));
        //        // trace.addTlsAction(new ReceiveAction(new SmtpEHLOReply()));
        //
        //        trace.addTlsAction(new STARTTLSAction());
        //
        //        trace.addTlsAction(new SendAction(new SmtpQUITCommand()));
        //        trace.addTlsAction(new ReceiveAction(new SmtpQUITReply()));

        System.out.println(trace);
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

        System.out.println(state.getWorkflowTrace());
        System.out.println(state.getContext().getLayerStack().getHighestLayer().getLayerResult());
        assert state.getWorkflowTrace().executedAsPlanned();
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    void testSMTPSTARTTLSWorkflowFromFactory() throws JAXBException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        Config config = Config.createConfig();
        config.setDefaultClientConnection(new OutboundConnection(2525, "localhost"));
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(
                        WorkflowTraceType.SMTP_STARTTLS, RunningModeType.CLIENT);
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

        System.out.println(state.getWorkflowTrace().executedAsPlanned());
        String res = WorkflowTraceSerializer.write(state.getWorkflowTrace());
        System.out.println(res);
    }
}
