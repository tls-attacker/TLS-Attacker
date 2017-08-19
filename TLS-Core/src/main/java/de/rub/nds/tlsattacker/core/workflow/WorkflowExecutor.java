/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public abstract class WorkflowExecutor {

    protected static final Logger LOGGER = LogManager.getLogger(WorkflowExecutor.class.getName());

    protected final WorkflowExecutorType type;

    protected final State state;
    protected final Config config;

    public WorkflowExecutor(WorkflowExecutorType type, State state) {
        this.type = type;
        this.state = state;
        this.config = state.getConfig();
        initWorkflowTrace();
    }

    /**
     * Initialization Order 1) Check WorkflowTrace in Config 2) Check
     * WorkflowTraceInput in Config 3) Check WorkflowTraceType in Config If
     * nothing set throw configuration exception
     */
    private void initWorkflowTrace() {
        WorkflowTrace trace = null;

        if (state.getWorkflowTrace() != null) {
            trace = state.getWorkflowTrace();
        } else if (config.getWorkflowInput() != null) {
            try {
                trace = WorkflowTraceSerializer.read(new FileInputStream(new File(config.getWorkflowInput())));
            } catch (FileNotFoundException ex) {
                LOGGER.warn("Could not read WorkflowTrace. File not found.");
                LOGGER.debug(ex);
            } catch (JAXBException | IOException | XMLStreamException ex) {
                LOGGER.warn("Could not read WorkflowTrace.");
                LOGGER.debug(ex);
            }
        } else if (config.getWorkflowTraceType() != null) {
            TlsContext ctx;
            try {
                ctx = state.getTlsContext();
            } catch (ConfigurationException ex) {
                throw new ConfigurationException("Can only configure workflow trace for"
                        + " a single context, but multiple contexts are defined.", ex);
            }
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(ctx);
            trace = factory.createWorkflowTrace(config.getWorkflowTraceType());
        }

        if (trace == null) {
            throw new ConfigurationException("Could not initialize WorkflowTrace in TLSContext");
        } else {
            state.setWorkflowTrace(trace);
        }
    }

    protected void storeTrace() {

        if (config.getWorkflowOutput() != null && !config.getWorkflowOutput().isEmpty()) {
            try {
                File f = new File(config.getWorkflowOutput());
                if (f.isDirectory()) {
                    f = new File(config.getWorkflowOutput() + "trace-" + RandomHelper.getRandom().nextInt());
                }
                WorkflowTraceSerializer.write(f, state.getWorkflowTrace());
            } catch (JAXBException | IOException ex) {
                LOGGER.info("Could not serialize WorkflowTrace.");
                LOGGER.debug(ex);
            }
        }
    }

    public abstract void executeWorkflow() throws WorkflowExecutionException;

}
