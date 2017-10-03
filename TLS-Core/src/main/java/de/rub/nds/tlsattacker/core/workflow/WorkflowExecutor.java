/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Random;
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

    /**
     * Prepare a workflow trace for execution according to the given state and
     * executor type. Try various ways to initialize a workflow trace and add it
     * to the state. For workflow creation, use the first method which does not
     * return null, in the following order: state.getWorkflowTrace(),
     * state.config.getWorkflowInput(), config.getWorkflowTraceType().
     * 
     * @param type
     *            of the workflow executor (currently only DEFAULT)
     * @param state
     *            to work on
     */
    public WorkflowExecutor(WorkflowExecutorType type, State state) {
        this.type = type;
        this.state = state;
        this.config = state.getConfig();
        initWorkflowTrace();
    }

    private void initWorkflowTrace() {
        WorkflowTrace trace = null;

        if (state.getWorkflowTrace() != null) {
            return;
        }

        if (config.getWorkflowInput() != null) {
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
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            trace = factory.createWorkflowTrace(config.getWorkflowTraceType(), state.getRunningMode());
        }

        if (trace == null) {
            throw new ConfigurationException("Could not initialize WorkflowTrace in TLSContext");
        } else {
            state.setWorkflowTrace(trace);
        }
    }

    protected void storeTrace() {
        Random random = new Random();
        if (config.getWorkflowOutput() != null && !config.getWorkflowOutput().isEmpty()) {
            try {
                File f = new File(config.getWorkflowOutput());
                if (f.isDirectory()) {
                    f = new File(config.getWorkflowOutput() + "trace-" + random.nextInt());
                }
                WorkflowTraceUtil.stripDefaultsForSerialization(state.getWorkflowTrace(), config,
                        state.getRunningMode());
                WorkflowTraceSerializer.write(f, state.getWorkflowTrace());
            } catch (JAXBException | IOException ex) {
                LOGGER.info("Could not serialize WorkflowTrace.");
                LOGGER.debug(ex);
            }
        }
    }

    public abstract void executeWorkflow() throws WorkflowExecutionException;

}
