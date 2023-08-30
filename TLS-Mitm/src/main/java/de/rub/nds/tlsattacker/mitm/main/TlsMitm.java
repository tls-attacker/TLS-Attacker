/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.mitm.config.MitmCommandConfig;
import java.io.File;
import java.io.FileInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsMitm implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger();

    private String[] args;

    public TlsMitm(String... args) {
        this.args = args;
    }

    public void run()
            throws ParameterException, WorkflowExecutionException, ConfigurationException {

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
            WorkflowTrace trace = null;
            if (cmdConfig.getWorkflowInput() != null) {
                LOGGER.debug("Reading workflow trace from " + cmdConfig.getWorkflowInput());
                try (FileInputStream fis = new FileInputStream(cmdConfig.getWorkflowInput())) {
                    trace = WorkflowTraceSerializer.secureRead(fis);
                }
            }
            State state = executeMitmWorkflow(config, trace);
            if (cmdConfig.getWorkflowOutput() != null) {
                trace = state.getWorkflowTrace();
                LOGGER.debug("Writing workflow trace to " + cmdConfig.getWorkflowOutput());
                WorkflowTraceSerializer.write(new File(cmdConfig.getWorkflowOutput()), trace);
            }
        } catch (WorkflowExecutionException wee) {
            LOGGER.error(
                    "The TLS protocol flow was not executed completely. "
                            + wee.getLocalizedMessage()
                            + " - See debug messages for more details.");
            LOGGER.error(wee.getLocalizedMessage());
            LOGGER.debug(wee);
            throw wee;
        } catch (ConfigurationException ce) {
            LOGGER.error(
                    "Encountered a ConfigurationException aborting. "
                            + ce.getLocalizedMessage()
                            + " - See debug messages for more details.");
            LOGGER.debug(ce.getLocalizedMessage(), ce);
            throw ce;
        } catch (ParameterException pe) {
            LOGGER.error("Could not parse provided parameters. " + pe.getLocalizedMessage());
            LOGGER.info("Try -help");
            throw pe;
        } catch (Exception E) {
            LOGGER.error(E);
        }
    }

    public State executeMitmWorkflow(Config config, WorkflowTrace trace)
            throws ConfigurationException, WorkflowExecutionException {
        LOGGER.debug("Creating and launching mitm.");
        State state;

        if (trace == null) {
            state = new State(config);
        } else {
            state = new State(config, trace);
        }
        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        return state;
    }
}
