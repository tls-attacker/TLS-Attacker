/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.server;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ListDelegate;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.server.config.ServerCommandConfig;
import java.io.File;
import java.io.FileInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        ServerCommandConfig config = new ServerCommandConfig(new GeneralDelegate());
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

            Config tlsConfig = null;
            try {
                tlsConfig = config.createConfig();
                WorkflowTrace trace = null;
                if (config.getWorkflowInput() != null) {
                    LOGGER.debug("Reading workflow trace from " + config.getWorkflowInput());
                    trace =
                        WorkflowTraceSerializer.secureRead(new FileInputStream(new File(config.getWorkflowInput())));
                }
                TlsServer server = new TlsServer();
                State state = server.execute(tlsConfig, trace);
                if (config.getWorkflowOutput() != null) {
                    trace = state.getWorkflowTrace();
                    LOGGER.debug("Writing workflow trace to " + config.getWorkflowOutput());
                    WorkflowTraceSerializer.write(new File(config.getWorkflowOutput()), trace);
                }
            } catch (Exception e) {
                LOGGER.warn("Encountered a ConfigurationException aborting. Try -debug for more info", e);
                commander.usage();
            }
        } catch (ParameterException e) {
            LOGGER.warn("Could not parse provided parameters. Try -debug for more info");
            LOGGER.debug(e);
            commander.usage();
        }
    }
}
