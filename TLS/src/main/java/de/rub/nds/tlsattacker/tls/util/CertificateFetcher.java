/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.util;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ClientConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CertificateFetcher {

    private CertificateFetcher() {

    }

    public static PublicKey fetchServerPublicKey(String connect, List<CipherSuite> cipherSuites) {
	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect(connect);
	config.setCipherSuites(cipherSuites);
	X509CertificateObject cert = fetchServerCertificate(config);
	return cert.getPublicKey();
    }

    public static X509CertificateObject fetchServerCertificate(String connect, List<CipherSuite> cipherSuites) {
	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect(connect);
	config.setCipherSuites(cipherSuites);
	return fetchServerCertificate(config);
    }

    public static PublicKey fetchServerPublicKey(ClientCommandConfig config) {
	X509CertificateObject cert = fetchServerCertificate(config);
	return cert.getPublicKey();
    }

    public static X509CertificateObject fetchServerCertificate(ClientCommandConfig config) {
	ConfigHandler configHandler = new ClientConfigHandler();
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext context = configHandler.initializeTlsContext(config);

	context.setProtocolVersion(config.getProtocolVersion());
	context.setSelectedCipherSuite(config.getCipherSuites().get(0));
	WorkflowTrace workflowTrace = new WorkflowTrace();
	List<ProtocolMessage> protocolMessages = new LinkedList<>();
	ClientHelloMessage clientHellp = new ClientHelloMessage();
	protocolMessages.add(clientHellp);
	workflowTrace.add(new SendAction(protocolMessages));
	protocolMessages = new LinkedList<>();
	protocolMessages.add(new ServerHelloMessage());
	protocolMessages.add(new CertificateMessage());
	workflowTrace.add(new ReceiveAction(protocolMessages));
	clientHellp.setSupportedCipherSuites(config.getCipherSuites());
	clientHellp.setSupportedCompressionMethods(config.getCompressionMethods());

	WorkflowConfigurationFactory.initializeClientHelloExtensions(config, clientHellp);
	context.setWorkflowTrace(workflowTrace);

	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, context);

	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();

	return context.getX509ServerCertificateObject();
    }
}
