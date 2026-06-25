/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.exception.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.ftp.command.FtpAUTHCommand;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpAUTHReply;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpInitialGreeting;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
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
 * Integration tests for the FTP STARTTLS (RFC 4217) control-connection upgrade. Experimental:
 * requires a running FTP server with explicit FTPS support (e.g. vsftpd with ssl_enable=YES), which
 * the CI does not provide.
 */
@Disabled("CI does not provide a proper FTP server setup")
public class FTPWorkflowTestBench {
    int PLAIN_PORT = 21;
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

    /** Manually built control-connection upgrade: greeting (220), AUTH TLS, reply (234). */
    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlowSimpleAuth() throws IOException, JAXBException {
        initializeConfig(PLAIN_PORT, StackConfiguration.FTP);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new ReceiveAction(new FtpInitialGreeting()));
        trace.addTlsAction(new SendAction(new FtpAUTHCommand()));
        trace.addTlsAction(new ReceiveAction(new FtpAUTHReply()));

        runWorkflowTrace(trace);
    }

    /**
     * Full STARTTLS path via the factory: greeting -> AUTH TLS -> 234 -> TLS handshake. This leaves
     * a working TLS stack behind so downstream TLS analysis (version detection, DROWN,
     * Bleichenbacher, etc.) can run on the upgraded connection.
     */
    @Tag(TestCategories.INTEGRATION_TEST)
    @Test
    public void testWorkFlowSTARTTLS() throws IOException, JAXBException {
        initializeConfig(PLAIN_PORT, StackConfiguration.FTP);

        config.setStarttlsType(StarttlsType.FTP);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(WorkflowTraceType.FTPS, RunningModeType.CLIENT);

        runWorkflowTrace(trace);
    }
}
