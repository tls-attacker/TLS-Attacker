/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.exception.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.pop3.command.*;
import de.rub.nds.tlsattacker.core.pop3.reply.*;
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
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.jupiter.api.*;

/**
 * Integration tests for the POP3 protocol. Experimental: Requires a running POP3 server, which the
 * CI does not provide.
 */
@Disabled("CI does not provide a proper POP3 server setup")
public class POP3WorkflowTestBench {
    int PLAIN_PORT = 11100;
    int IMPLICIT_TLS_PORT = 11101;
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
        assertTrue(state.getWorkflowTrace().executedAsPlanned());
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlowPop3Simple() throws IOException, JAXBException {
        initializeConfig(PLAIN_PORT, StackConfiguration.POP3);

        WorkflowTrace trace = new WorkflowTrace();
        // Example pop3 session:
        trace.addTlsAction(new ReceiveAction(new Pop3InitialGreeting()));
        trace.addTlsAction(new SendAction(new Pop3USERCommand()));
        trace.addTlsAction(new ReceiveAction(new Pop3USERReply()));
        trace.addTlsAction(new SendAction(new Pop3PASSCommand()));
        trace.addTlsAction(new ReceiveAction(new Pop3PASSReply()));
        trace.addTlsAction(new SendAction(new Pop3STATCommand()));
        trace.addTlsAction(new ReceiveAction(new Pop3STATReply()));
        trace.addTlsAction(new SendAction(new Pop3RETRCommand()));
        trace.addTlsAction(new ReceiveAction(new Pop3RETRReply()));
        trace.addTlsAction(new SendAction(new Pop3QUITCommand()));
        trace.addTlsAction(new ReceiveAction(new Pop3QUITReply()));

        runWorkflowTrace(trace);
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlowSTARTTLS() throws IOException, JAXBException {
        initializeConfig(PLAIN_PORT, StackConfiguration.POP3);

        config.setStarttlsType(StarttlsType.POP3);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(WorkflowTraceType.POP3S, RunningModeType.CLIENT);

        runWorkflowTrace(trace);
    }

    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlowPOP3S() throws IOException, JAXBException {
        initializeConfig(PLAIN_PORT, StackConfiguration.POP3);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(WorkflowTraceType.POP3S, RunningModeType.CLIENT);

        runWorkflowTrace(trace);
    }
}
