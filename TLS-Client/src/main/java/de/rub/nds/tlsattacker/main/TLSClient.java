/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.main;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.client.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A TLS-Client implementation that supports custom Workflows
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSClient {

    private static final Logger LOGGER = LogManager.getLogger("Client");

    public static void main(String args[]) {
        ClientCommandConfig config = new ClientCommandConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        Exception ex = null;
        try {
            commander.parse(args);
        } catch (Exception E) {
            LOGGER.info("Could not parse provided parameters");
            LOGGER.debug(E);
            commander.usage();
            ex = E;
        }
        if (ex == null) {
            // Cmd was parsable
            TlsConfig tlsConfig = null;
            try {
                tlsConfig = config.createConfig();
                TLSClient client = new TLSClient();
                client.startTlsClient(tlsConfig);
            } catch (ConfigurationException E) {
                LOGGER.info("Encountered a ConfigurationException aborting.");
                LOGGER.debug(E);
            }
        }
    }

    public void startTlsClient(TlsConfig config) {
        TlsContext tlsContext = new TlsContext(config);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(config.getExecutorType(),
                tlsContext);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        }
    }
}
