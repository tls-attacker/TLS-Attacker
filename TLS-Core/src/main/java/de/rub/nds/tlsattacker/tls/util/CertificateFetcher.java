/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.util;

import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.security.PublicKey;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CertificateFetcher {

    private static final Logger LOGGER = LogManager.getLogger(CertificateFetcher.class);

    public static PublicKey fetchServerPublicKey(String connect, List<CipherSuite> cipherSuites) {
        TlsConfig config = new TlsConfig();
        config.setHost(connect);
        config.setSupportedCiphersuites(cipherSuites);
        X509CertificateObject cert = fetchServerCertificate(config);
        return cert.getPublicKey();
    }

    public static X509CertificateObject fetchServerCertificate(String connect, List<CipherSuite> cipherSuites) {
        TlsConfig config = new TlsConfig();
        config.setHost(connect);
        config.setSupportedCiphersuites(cipherSuites);
        return fetchServerCertificate(config);
    }

    public static PublicKey fetchServerPublicKey(TlsConfig config) {
        X509CertificateObject cert = fetchServerCertificate(config);
        return cert.getPublicKey();
    }

    public static X509CertificateObject fetchServerCertificate(TlsConfig config) {
        ConfigHandler configHandler = new ConfigHandler();
        TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
        TlsContext context = configHandler.initializeTlsContext(config);

        context.setSelectedProtocolVersion(config.getHighestProtocolVersion());
        context.setSelectedCipherSuite(config.getSupportedCiphersuites().get(0));
        WorkflowTrace workflowTrace = new WorkflowTrace();
        List<ProtocolMessage> protocolMessages = new LinkedList<>();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        protocolMessages.add(clientHello);
        workflowTrace.add(new SendAction(protocolMessages));
        protocolMessages = new LinkedList<>();
        protocolMessages.add(new ServerHelloMessage(config));
        protocolMessages.add(new CertificateMessage(config));
        workflowTrace.add(new ReceiveAction(protocolMessages));
        context.setWorkflowTrace(workflowTrace);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, context);
        try {
            workflowExecutor.executeWorkflow();
        } catch (Exception E) {
            LOGGER.warn("Error while Fetching Certificate", E);
        }
        transportHandler.closeConnection();
        return context.getX509ServerCertificateObject();
    }

    private CertificateFetcher() {

    }
}
