/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import java.io.IOException;
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

    private void initWorkflowTrace() {

        if (context.getWorkflowTrace() == null) {
            context.setWorkflowTrace(context.getConfig().getWorkflowTrace());
        }
        if (context.getWorkflowTrace() == null) {
            if (context.getConfig().getWorkflowTraceType() == null) {
                context.setWorkflowTrace(new WorkflowConfigurationFactory(context.getConfig())
                        .createWorkflowTrace(WorkflowTraceType.HANDSHAKE));
            } else {
                context.setWorkflowTrace(new WorkflowConfigurationFactory(context.getConfig())
                        .createWorkflowTrace(context.getConfig().getWorkflowTraceType()));
            }
        }
        if (context.getWorkflowTrace() == null) {
            throw new ConfigurationException("Could not initialize WorkflowTrace in TLSContext");
        }
    }

    protected final TransportHandler createTransportHandler() throws ConfigurationException {
        String[] hp = context.getConfig().getHost().split(":");
        String host = hp[0];
        int port;
        if (context.getConfig().getConnectionEnd() == ConnectionEnd.SERVER) {
            port = context.getConfig().getServerPort();
        } else if (hp.length == 1) {
            port = 443;
        } else {
            port = Integer.parseInt(hp[1]);
        }
        TransportHandler th = TransportHandlerFactory.createTransportHandler(host, port, context.getConfig()
                .getConnectionEnd(), context.getConfig().getTlsTimeout(), context.getConfig().getTimeout(), context
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

    public abstract void executeWorkflow() throws WorkflowExecutionException;

}
