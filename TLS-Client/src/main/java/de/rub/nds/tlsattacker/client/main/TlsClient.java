/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.client.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.client.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.config.TlsConfig;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A TLS-Client implementation that supports custom Workflows
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsClient {

    private static final Logger LOGGER = LogManager.getLogger("Client");

    public static void main(String args[]) {
        ClientCommandConfig config = new ClientCommandConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        Exception ex = null;
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            // Cmd was parsable
            TlsConfig tlsConfig = null;
            try {
                tlsConfig = config.createConfig();
                TlsClient client = new TlsClient();
                client.startTlsClient(tlsConfig);
            } catch (ConfigurationException E) {
                LOGGER.info("Encountered a ConfigurationException aborting.");
                LOGGER.debug(E);
            }
        } catch (ParameterException E) {
            LOGGER.info("Could not parse provided parameters");
            LOGGER.debug(E);
            commander.usage();
            ex = E;
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
