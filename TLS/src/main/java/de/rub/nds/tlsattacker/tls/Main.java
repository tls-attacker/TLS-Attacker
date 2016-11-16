/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.ServerCommandConfig;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.SessionResumptionWorkflowConfiguration;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.FileOutputStream;

/**
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 * @author Philip Riese <philip.riese@rub.de>
 */
public class Main {

    public static void main(String[] args) throws Exception {

        GeneralConfig generalConfig = new GeneralConfig();
        JCommander jc = new JCommander(generalConfig);

        ServerCommandConfig server = new ServerCommandConfig();
        jc.addCommand(ServerCommandConfig.COMMAND, server);
        ClientCommandConfig client = new ClientCommandConfig();
        jc.addCommand(ClientCommandConfig.COMMAND, client);

        jc.parse(args);

        if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
            jc.usage();
            return;
        }

        CommandConfig config;
        if (jc.getParsedCommand().equals(ServerCommandConfig.COMMAND)) {
            config = server;
        } else {
            config = client;
        }

        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler(jc.getParsedCommand());
        configHandler.initialize(generalConfig);

        if (configHandler.printHelpForCommand(jc, config)) {
            return;
        }

        TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
        TlsContext tlsContext = configHandler.initializeTlsContext(config);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

        workflowExecutor.executeWorkflow();

        // if (config.isVerifyWorkflowCorrectness()) {
        // workflowExecutor.checkConfiguredProtocolMessagesOrder();
        // }

        transportHandler.closeConnection();

        // setting and executing the session resumption workflow trace
        if (config.isSessionResumption()) {
            TransportHandler transportHandlerSR = configHandler.initializeTransportHandler(config);

            SessionResumptionWorkflowConfiguration SRworkflow = new SessionResumptionWorkflowConfiguration(tlsContext,
                    config);
            SRworkflow.createWorkflow();

            WorkflowExecutor workflowExecutorSR = configHandler.initializeWorkflowExecutor(transportHandlerSR,
                    tlsContext);

            workflowExecutorSR.executeWorkflow();

            transportHandlerSR.closeConnection();
        }

        if (config.getWorkflowOutput() != null && !config.getWorkflowOutput().isEmpty()) {
            FileOutputStream fos = new FileOutputStream(config.getWorkflowOutput());
            WorkflowTraceSerializer.write(fos, tlsContext.getWorkflowTrace());
        }
    }
}
