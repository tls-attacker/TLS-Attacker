/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.client.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.client.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ListDelegate;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import java.io.File;
import java.io.FileInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A TLS-Client implementation that supports custom Workflows */
public class TlsClient {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        ClientCommandConfig config = new ClientCommandConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            ListDelegate list = (ListDelegate) config.getDelegate(ListDelegate.class);
            if (list.isSet()) {
                list.plotListing();
                return;
            }

            try {
                Config tlsConfig = config.createConfig();
                WorkflowTrace trace = null;
                if (config.getWorkflowInput() != null) {
                    LOGGER.debug("Reading workflow trace from " + config.getWorkflowInput());
                    try (FileInputStream fis = new FileInputStream(config.getWorkflowInput())) {
                        trace = WorkflowTraceSerializer.secureRead(fis);
                    }
                }
                TlsClient client = new TlsClient();
                State state = client.startTlsClient(tlsConfig, trace);
                if (config.getWorkflowOutput() != null) {
                    trace = state.getWorkflowTrace();
                    LOGGER.debug("Writing workflow trace to " + config.getWorkflowOutput());
                    WorkflowTraceSerializer.write(new File(config.getWorkflowOutput()), trace);
                }
            } catch (Exception e) {
                LOGGER.error(
                        "Encountered an uncaught Exception aborting. See debug for more info.", e);
            }
        } catch (ParameterException e) {
            LOGGER.error("Could not parse provided parameters. " + e.getLocalizedMessage(), e);
            commander.usage();
        }
    }

    public State startTlsClient(Config config, WorkflowTrace trace) {
        State state;
        if (trace == null) {
            state = new State(config);
        } else {
            state = new State(config, trace);
        }
        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.warn(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        }
        return state;
    }
}
