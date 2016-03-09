/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.security.PublicKey;
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
	ClientHelloMessage ch = new ClientHelloMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(ch);
	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new CertificateMessage(ConnectionEnd.SERVER));

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());

	WorkflowConfigurationFactory.initializeClientHelloExtensions(config, ch);
	workflowTrace.setProtocolMessages(protocolMessages);

	context.setWorkflowTrace(workflowTrace);

	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, context);

	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();

	return context.getX509ServerCertificateObject();
    }
}
