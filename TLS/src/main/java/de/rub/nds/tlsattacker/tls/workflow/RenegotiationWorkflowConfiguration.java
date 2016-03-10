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
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import static de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory.initializeProtocolMessageOrder;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates Workflowtrace for Renegotiation with Client Authentication
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class RenegotiationWorkflowConfiguration {

    private final TlsContext tlsContext;

    public RenegotiationWorkflowConfiguration(TlsContext tlsContext) {
	this.tlsContext = tlsContext;
    }

    public void createWorkflow() {
	ProtocolMessage lastMessage = tlsContext.getWorkflowTrace().getLastProtocolMesssage();
	WorkflowTrace workflowTrace;
	if (lastMessage.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
	    workflowTrace = createHandshakeWorkflow();
	} else if (lastMessage.getProtocolMessageType() == ProtocolMessageType.APPLICATION_DATA
		&& lastMessage.getMessageIssuer() == ConnectionEnd.CLIENT) {
	    workflowTrace = createFullWorkflow();
	} else {
	    workflowTrace = createFullSRWorkflow();
	}

	tlsContext.setWorkflowTrace(workflowTrace);

	initializeProtocolMessageOrder(tlsContext);
    }

    private WorkflowTrace createHandshakeWorkflow() {

	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new LinkedList<>();

	ClientHelloMessage ch = new ClientHelloMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(ch);

	List<CipherSuite> ciphers = new LinkedList<>();
	ciphers.add(tlsContext.getSelectedCipherSuite());
	ch.setSupportedCipherSuites(ciphers);
	List<CompressionMethod> compressions = new LinkedList<>();
	compressions.add(CompressionMethod.NULL);
	ch.setSupportedCompressionMethods(compressions);

	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new CertificateMessage(ConnectionEnd.SERVER));

	if (tlsContext.getSelectedCipherSuite().isEphemeral()) {
	    if (tlsContext.getSelectedCipherSuite().name().contains("_DHE_")) {
		protocolMessages.add(new DHEServerKeyExchangeMessage(ConnectionEnd.SERVER));
	    } else {
		protocolMessages.add(new ECDHEServerKeyExchangeMessage(ConnectionEnd.SERVER));
	    }
	}

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateRequestMessage(ConnectionEnd.SERVER));
	}

	protocolMessages.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateMessage(ConnectionEnd.CLIENT));
	}

	if (tlsContext.getSelectedCipherSuite().name().contains("_DH")) {
	    protocolMessages.add(new DHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	} else if (tlsContext.getSelectedCipherSuite().name().contains("_ECDH")) {
	    protocolMessages.add(new ECDHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	} else {
	    protocolMessages.add(new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	}

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateVerifyMessage(ConnectionEnd.CLIENT));
	}

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.CLIENT));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.SERVER));

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;

    }

    private WorkflowTrace createFullWorkflow() {

	WorkflowTrace workflowTrace = this.createHandshakeWorkflow();

	List<ProtocolMessage> protocolMessages = workflowTrace.getProtocolMessages();

	protocolMessages.add(new ApplicationMessage(ConnectionEnd.CLIENT));

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;
    }

    private WorkflowTrace createFullSRWorkflow() {

	WorkflowTrace workflowTrace = this.createFullWorkflow();

	List<ProtocolMessage> protocolMessages = workflowTrace.getProtocolMessages();

	protocolMessages.add(new ApplicationMessage(ConnectionEnd.SERVER));

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;
    }

}
