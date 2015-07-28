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

import de.rub.nds.tlsattacker.dtls.protocol.handshake.messages.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.workflow.factory.*;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.messages.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.messages.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.protocol.alert.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.protocol.alert.messages.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.HandshakeMessageFactory;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.messages.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.util.ArrayList;
import java.util.List;

/**
 * Creates configuration of implemented RSA functionality in the protocol.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DtlsRsaWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    private final CommandConfig config;

    private HandshakeMessageFactory hmFactory;

    DtlsRsaWorkflowConfigurationFactory(CommandConfig config) {
	this.config = config;
    }

    @Override
    public TlsContext createClientHelloTlsContext() {
	TlsContext context = new TlsContext();
	context.setProtocolVersion(config.getProtocolVersion());

	hmFactory = new HandshakeMessageFactory(context.getProtocolVersion());

	context.setSelectedCipherSuite(config.getCipherSuites().get(0));
	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new ArrayList<>();

	ClientHelloMessage ch = hmFactory.createHandshakeMessage(ClientHelloMessage.class, ConnectionEnd.CLIENT);
	protocolMessages.add(ch);

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());
	ch.setIncludeInDigest(false);

	initializeClientHelloExtensions(config, ch);

	HelloVerifyRequestMessage hvrm = hmFactory.createHandshakeMessage(HelloVerifyRequestMessage.class,
		ConnectionEnd.SERVER);
	hvrm.setIncludeInDigest(false);
	protocolMessages.add(hvrm);

	ch = hmFactory.createHandshakeMessage(ClientHelloMessage.class, ConnectionEnd.CLIENT);
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

	protocolMessages.add(hmFactory.createHandshakeMessage(ServerHelloMessage.class, ConnectionEnd.SERVER));
	protocolMessages.add(hmFactory.createHandshakeMessage(CertificateMessage.class, ConnectionEnd.SERVER));
	if (config.getKeystore() != null) {
	    protocolMessages.add(hmFactory
		    .createHandshakeMessage(CertificateRequestMessage.class, ConnectionEnd.SERVER));
	    protocolMessages.add(hmFactory.createHandshakeMessage(ServerHelloDoneMessage.class, ConnectionEnd.SERVER));

	    protocolMessages.add(hmFactory.createHandshakeMessage(CertificateMessage.class, ConnectionEnd.CLIENT));
	    protocolMessages.add(hmFactory.createHandshakeMessage(RSAClientKeyExchangeMessage.class,
		    ConnectionEnd.CLIENT));
	    protocolMessages
		    .add(hmFactory.createHandshakeMessage(CertificateVerifyMessage.class, ConnectionEnd.CLIENT));
	} else {
	    protocolMessages.add(hmFactory.createHandshakeMessage(ServerHelloDoneMessage.class, ConnectionEnd.SERVER));

	    protocolMessages.add(hmFactory.createHandshakeMessage(RSAClientKeyExchangeMessage.class,
		    ConnectionEnd.CLIENT));
	}

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(hmFactory.createHandshakeMessage(FinishedMessage.class, ConnectionEnd.CLIENT));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(hmFactory.createHandshakeMessage(FinishedMessage.class, ConnectionEnd.SERVER));

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

	AlertMessage alertMessage = new AlertMessage(ConnectionEnd.CLIENT);

	alertMessage.setConfig(AlertLevel.FATAL, AlertDescription.CLOSE_NOTIFY);

	protocolMessages.add(alertMessage);

	initializeProtocolMessageOrder(context);

	return context;
    }
}
