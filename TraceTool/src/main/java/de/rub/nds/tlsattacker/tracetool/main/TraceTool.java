/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tracetool.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.ConfigIO;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ListDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tracetool.config.TraceToolCommandConfig;
import java.io.File;
import java.io.IOException;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * TraceTool allows inspection and modification of TLS-Attacker workflow traces.
 *
 * The tools works on TLS-Attackers XML formatted workflow traces and can
 * <ul>
 * <li>Generate trace templates for common workflows (in XML)</li>
 * <li>Apply filters to workflow trace inputs</li>
 * <li>Verify if a workflow trace is normalized, i.e. well defined for
 * standalone execution without the need of an additional Configuration</li>
 * </ul>
 */
public class TraceTool {

    private static final Logger LOGGER = LogManager.getLogger();

    private String[] args;

    public TraceTool(String... args) {
        this.args = args;
    }

    public void run() throws ParameterException, ConfigurationException, JAXBException, IOException {

        TraceToolCommandConfig cmdConfig = new TraceToolCommandConfig(new GeneralDelegate());
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
            State state = new State(config);
            if (config.getWorkflowOutput() == null || config.getWorkflowOutput().isEmpty()) {
                WorkflowTrace filtered = state.getFilteredTraceCopy();
                String xml = WorkflowTraceSerializer.write(filtered);
                System.out.println(xml);
            } else {
                state.storeTrace();
            }
            if (config.getConfigOutput() != null) {
                ConfigIO.write(config, new File(config.getConfigOutput()));
            }
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

}
