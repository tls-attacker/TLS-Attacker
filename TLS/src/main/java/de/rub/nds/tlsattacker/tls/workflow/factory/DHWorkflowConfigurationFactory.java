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
package de.rub.nds.tlsattacker.tls.workflow.factory;

import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.messages.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.messages.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.messages.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates configuration of implemented DH(E) functionality in the protocol.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DHWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    private final CommandConfig config;

    DHWorkflowConfigurationFactory(CommandConfig config) {
	this.config = config;
    }

    @Override
    public TlsContext createClientHelloTlsContext() {
	TlsContext context = new TlsContext();
	context.setProtocolVersion(config.getProtocolVersion());
	context.setSelectedCipherSuite(config.getCipherSuites().get(0));
	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new LinkedList<>();

	ClientHelloMessage ch = new ClientHelloMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(ch);

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());

	initializeClientHelloExtensions(config, ch);

	workflowTrace.setProtocolMessages(protocolMessages);

	context.setWorkflowTrace(workflowTrace);
	initializeProtocolMessageOrder(context);

	return context;
    }

    @Override
    public TlsContext createHandshakeTlsContext() {
	TlsContext context = this.createClientHelloTlsContext();

	List<ProtocolMessage> protocolMessages = context.getWorkflowTrace().getProtocolMessages();

	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new CertificateMessage(ConnectionEnd.SERVER));

	if (config.getCipherSuites().get(0).isEphemeral()) {
	    protocolMessages.add(new DHEServerKeyExchangeMessage(ConnectionEnd.SERVER));
	}
	if (config.getKeystore() != null) {
	    protocolMessages.add(new CertificateRequestMessage(ConnectionEnd.SERVER));
	    protocolMessages.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	    protocolMessages.add(new CertificateMessage(ConnectionEnd.CLIENT));
	    protocolMessages.add(new DHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	    protocolMessages.add(new CertificateVerifyMessage(ConnectionEnd.CLIENT));
	} else {
	    protocolMessages.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	    protocolMessages.add(new DHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	}
	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.CLIENT));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.SERVER));

	initializeProtocolMessageOrder(context);

	return context;
    }

    @Override
    public TlsContext createFullTlsContext() {
	TlsContext context = this.createHandshakeTlsContext();

	List<ProtocolMessage> protocolMessages = context.getWorkflowTrace().getProtocolMessages();

	protocolMessages.add(new ApplicationMessage(ConnectionEnd.CLIENT));

	if (config.getHeartbeatMode() != null) {
	    protocolMessages.add(new HeartbeatMessage(ConnectionEnd.CLIENT));
	    protocolMessages.add(new HeartbeatMessage(ConnectionEnd.SERVER));
	}

	initializeProtocolMessageOrder(context);

	return context;
    }
}
