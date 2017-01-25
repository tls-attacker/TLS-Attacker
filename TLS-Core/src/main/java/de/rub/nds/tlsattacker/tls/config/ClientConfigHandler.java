/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config;

import de.rub.nds.tlsattacker.tls.util.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ClientConfigHandler extends ConfigHandler {

    @Override
    public TransportHandler initializeTransportHandler(CommandConfig config) throws ConfigurationException {
        ClientCommandConfig ccConfig = (ClientCommandConfig) config;
        TransportHandler th = TransportHandlerFactory.createTransportHandler(config.getTransportHandlerType(),
                config.getTlsTimeout());
        try {
            String[] hp = ccConfig.getConnect().split(":");
            String host = hp[0];
            int port = Integer.parseInt(hp[1]);
            th.initialize(host, port);
            // th.setTimeout(config.getTlsTimeout());//TODO
            return th;
        } catch (ArrayIndexOutOfBoundsException | NullPointerException | NumberFormatException ex) {
            throw new ConfigurationException(ccConfig.getConnect()
                    + " is an invalid string for host:port configuration", ex);
        } catch (IOException ex) {
            throw new ConfigurationException("Unable to initialize the transport handler with: "
                    + ccConfig.getConnect(), ex);
        }
    }

    @Override
    public TlsContext initializeTlsContext(CommandConfig config) {
        ClientCommandConfig ccConfig = (ClientCommandConfig) config;
        TlsContext tlsContext;
        WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(config);
        if (ccConfig.getWorkflowInput() != null) {
            try {
                tlsContext = new TlsContext(config.getProtocolVersion());
                FileInputStream fis = new FileInputStream(ccConfig.getWorkflowInput());
                WorkflowTrace workflowTrace = WorkflowTraceSerializer.read(fis);
                tlsContext.setWorkflowTrace(workflowTrace);
                if (workflowTrace.getProtocolVersion() != null) {
                    tlsContext.setProtocolVersion(workflowTrace.getProtocolVersion());
                }
                WorkflowConfigurationFactory.initializeProtocolMessageOrder(tlsContext);
            } catch (IOException | JAXBException | XMLStreamException ex) {
                throw new ConfigurationException("The workflow trace could not be loaded from "
                        + ccConfig.getWorkflowInput(), ex);
            }
        } else {
            switch (ccConfig.getWorkflowTraceType()) {
                case FULL_SERVER_RESPONSE:
                    tlsContext = factory.createFullServerResponseTlsContext(ConnectionEnd.CLIENT);
                    break;
                case FULL:
                    tlsContext = factory.createFullTlsContext(ConnectionEnd.CLIENT);
                    break;
                case HANDSHAKE:
                    tlsContext = factory.createHandshakeTlsContext(ConnectionEnd.CLIENT);
                    break;
                case CLIENT_HELLO:
                    tlsContext = factory.createClientHelloTlsContext(ConnectionEnd.CLIENT);
                    break;
                default:
                    throw new ConfigurationException("not supported workflow type: " + ccConfig.getWorkflowTraceType());
            }

        }
        // host for application data
        String[] hp = ccConfig.getConnect().split(":");
        String host = hp[0];
        tlsContext.setHost(host);
        tlsContext.setMyConnectionEnd(ConnectionEnd.CLIENT);
        tlsContext.setClientAuthentication(config.isClientAuthentication());

        if (config.getKeystore() != null) {
            try {
                KeyStore ks = KeystoreHandler.loadKeyStore(config.getKeystore(), config.getPassword());
                tlsContext.setKeyStore(ks);
                tlsContext.setAlias(config.getAlias());
                tlsContext.setPassword(config.getPassword());
                if (LOGGER.isDebugEnabled()) {
                    Enumeration<String> aliases = ks.aliases();
                    LOGGER.debug("Successfully read keystore with the following aliases: ");
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        LOGGER.debug("  {}", alias);
                    }
                }
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
                LOGGER.error(ex);
                throw new ConfigurationException(ex.getLocalizedMessage(), ex);
            }
        }

        return tlsContext;
    }

    @Override
    public WorkflowExecutor initializeWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
        WorkflowExecutor executor = WorkflowExecutorFactory.createWorkflowExecutor(transportHandler, tlsContext);
        return executor;
    }

}
