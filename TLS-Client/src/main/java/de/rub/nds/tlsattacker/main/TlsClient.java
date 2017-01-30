/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.main;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.client.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.util.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A TLS-TlsClient implementation that supports custom Workflows
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsClient {

    private static final Logger LOGGER = LogManager.getLogger(TlsClient.class);

    public static void main(String args[]) {
        ClientCommandConfig config = new ClientCommandConfig();
        JCommander commander = new JCommander(config);
        Exception ex = null;
        try {
            commander.parse(args);
        } catch (Exception E) {
            LOGGER.info("Could not parse provided parameters");
            commander.usage();
            ex = E;
        }
        if (ex == null) {
            // Cmd was parsable
            TlsConfig tlsConfig = null;
            try {
                tlsConfig = config.createConfig();
                TlsClient client = new TlsClient();
                client.startTlsClient(tlsConfig);
            } catch (ConfigurationException E) {
                LOGGER.info("Could not initialize Configuration", E);
            }

        }
    }

    public void startTlsClient(TlsConfig config) {
        ConfigHandler handler = new ConfigHandler();
        TransportHandler transportHandler = handler.initializeTransportHandler(config);
        TlsContext tlsContext = handler.initializeTlsContext(config);
        WorkflowExecutor workflowExecutor = handler.initializeWorkflowExecutor(transportHandler, tlsContext);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info(ex.getLocalizedMessage(), ex);
            LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
        }

        transportHandler.closeConnection();

        if (config.getWorkflowOutput() != null && !config.getWorkflowOutput().isEmpty()) {
            FileOutputStream fos = null;
            try {
                fos = new FileOutputStream(config.getWorkflowOutput());
                WorkflowTraceSerializer.write(fos, tlsContext.getWorkflowTrace());
            } catch (FileNotFoundException ex) {
                java.util.logging.Logger.getLogger(TlsClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (JAXBException | IOException ex) {
                LOGGER.info("Could not serialize WorkflowTrace.", ex);
            } finally {
                try {
                    fos.close();
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(TlsClient.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

}
