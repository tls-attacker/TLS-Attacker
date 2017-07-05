/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.TlsConfig;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public abstract class WorkflowExecutor {

    protected static final Logger LOGGER = LogManager.getLogger("WorkflowExecutor");

    protected final ExecutorType type;

    protected final TlsContext context;

    public WorkflowExecutor(ExecutorType type, TlsContext context) {
        this.type = type;
        this.context = context;
        initWorkflowTrace();
    }

    /**
     * Initialization Order: 1. Check WorkflowTrace in Config 2. Check
     * WorkflowTraceInput in Config 3. Check WorkflowTraceType in Config 4. If
     * nothing set throw configuration exception
     */
    private void initWorkflowTrace() {
        WorkflowTrace trace = null;
        if (context.getConfig().getWorkflowTrace() != null) {
            trace = context.getConfig().getWorkflowTrace();
        } else if (context.getConfig().getWorkflowInput() != null) {
            try {
                // Read workflowinput
                trace = WorkflowTraceSerializer.read(new FileInputStream(new File(context.getConfig()
                        .getWorkflowInput())));
            } catch (FileNotFoundException ex) {
                LOGGER.warn("Could not read WorkflowTrace. File not found.");
                LOGGER.debug(ex);
            } catch (JAXBException | IOException | XMLStreamException ex) {
                LOGGER.warn("Could not read WorkflowTrace.");
                LOGGER.debug(ex);
            }
        } else if (context.getConfig().getWorkflowTraceType() != null) {
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(context.getConfig());
            trace = factory.createWorkflowTrace(context.getConfig().getWorkflowTraceType());
        }

        if (trace == null) {
            throw new ConfigurationException("Could not initialize WorkflowTrace in TLSContext");
        } else {
            context.setWorkflowTrace(trace);
        }
    }

    protected final TransportHandler createTransportHandler() throws ConfigurationException {
        String host = context.getConfig().getHost();
        int port = context.getConfig().getPort();
        TransportHandler th = TransportHandlerFactory.createTransportHandler(host, port, context.getConfig()
                .getConnectionEndType(), context.getConfig().getTlsTimeout(), context.getConfig().getTimeout(), context
                .getConfig().getTransportHandlerType());
        try {

            th.initialize();
            return th;
        } catch (NullPointerException | NumberFormatException ex) {
            throw new ConfigurationException(context.getConfig().getHost()
                    + " is an invalid string for host:port configuration", ex);
        } catch (IOException ex) {
            throw new ConfigurationException("Unable to initialize the transport handler with: "
                    + context.getConfig().getHost(), ex);
        }
    }

    protected void storeTrace() {
        TlsConfig config = context.getConfig();

        if (config.getWorkflowOutput() != null && !config.getWorkflowOutput().isEmpty()) {
            FileOutputStream fos = null;
            try {
                File f = new File(config.getWorkflowOutput());
                if (f.isDirectory()) {
                    f = new File(config.getWorkflowOutput() + "trace-" + RandomHelper.getRandom().nextInt());
                }
                fos = new FileOutputStream(f);
                WorkflowTraceSerializer.write(fos, context.getWorkflowTrace());
            } catch (JAXBException | IOException ex) {
                LOGGER.info("Could not serialize WorkflowTrace.");
                LOGGER.debug(ex);
            } finally {
                try {
                    fos.close();
                } catch (IOException ex) {
                    LOGGER.info("Could not serialize WorkflowTrace.");
                    LOGGER.debug(ex);
                }
            }
        }
    }

    public abstract void executeWorkflow() throws WorkflowExecutionException;

}
