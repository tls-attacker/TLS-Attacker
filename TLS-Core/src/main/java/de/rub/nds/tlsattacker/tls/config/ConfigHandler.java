/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.GenericWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ConfigHandler {

    static final Logger LOGGER = LogManager.getLogger(ConfigHandler.class);

    public TlsConfig initialize(TLSDelegateConfig config) {
        return config.createConfig();
    }

    public boolean printHelpForCommand(JCommander jc, TLSDelegateConfig config) {
        if (config.getGeneralDelegate().isHelp()) {
            jc.usage(jc.getParsedCommand());
            return true;
        }
        return false;
    }

    public TransportHandler initializeTransportHandler(TlsConfig config) throws ConfigurationException {
        String[] hp = config.getHost().split(":");
        String host = hp[0];
        int port;
        if (config.getMyConnectionEnd() == ConnectionEnd.SERVER) {
            port = config.getServerPort();
        } else if (hp.length == 1) {
            port = 443;
        } else {
            port = Integer.parseInt(hp[1]);
        }
        TransportHandler th = TransportHandlerFactory.createTransportHandler(host, port, config.getMyConnectionEnd(),
                config.getTlsTimeout(), config.getTimeout(), config.getTransportHandlerType());
        try {

            th.initialize();
            return th;
        } catch (NullPointerException | NumberFormatException ex) {
            throw new ConfigurationException(config.getHost() + " is an invalid string for host:port configuration", ex);
        } catch (IOException ex) {
            throw new ConfigurationException("Unable to initialize the transport handler with: " + config.getHost(), ex);
        }
    }

    public TlsContext initializeTlsContext(TlsConfig config) {
        TlsContext context = new TlsContext(config);
        return context;
    }

    public WorkflowExecutor initializeWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
        return WorkflowExecutorFactory.createWorkflowExecutor(transportHandler, tlsContext);
    }
}
