/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.mitm.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ListDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.mitm.config.MitmCommandConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsMitm implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger();

    private String[] args;

    public TlsMitm(String... args) {
        this.args = args;
    }

    public void run() throws ParameterException, WorkflowExecutionException, ConfigurationException {

        MitmCommandConfig cmdConfig = new MitmCommandConfig(new GeneralDelegate());
        JCommander commander = new JCommander(cmdConfig);

        try {
            commander.parse(args);
        } catch (ParameterException pe) {
            LOGGER.error("Could not parse provided parameters. " + pe.getLocalizedMessage());
            LOGGER.info("Try -help");
            throw pe;
        }

        if (cmdConfig.getGeneralDelegate().isHelp()) {
            commander.usage();
            return;
        }
        ListDelegate list = (ListDelegate) cmdConfig.getDelegate(ListDelegate.class);
        if (list.isSet()) {
            list.plotListing();
            return;
        }

        try {
            Config config = cmdConfig.createConfig();
            executeMitmWorkflow(config);
        } catch (WorkflowExecutionException wee) {
            LOGGER.error("The TLS protocol flow was not executed completely. " + wee.getLocalizedMessage()
                    + " - See debug messages for more details.");
            LOGGER.error(wee.getLocalizedMessage());
            LOGGER.debug(wee);
            throw wee;
        } catch (ConfigurationException ce) {
            LOGGER.error("Encountered a ConfigurationException aborting. " + ce.getLocalizedMessage()
                    + " - See debug messages for more details.");
            LOGGER.debug(ce.getLocalizedMessage(), ce);
            throw ce;
        } catch (ParameterException pe) {
            LOGGER.error("Could not parse provided parameters. " + pe.getLocalizedMessage());
            LOGGER.info("Try -help");
            throw pe;
        }
    }

    public void executeMitmWorkflow(Config config) throws ConfigurationException, WorkflowExecutionException {
        LOGGER.debug("Creating and launching mitm.");
        State state = new State(config);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                config.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
    }
}
