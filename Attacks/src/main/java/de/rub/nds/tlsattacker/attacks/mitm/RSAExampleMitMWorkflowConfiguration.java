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
package de.rub.nds.tlsattacker.attacks.mitm;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import static de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory.initializeProtocolMessageOrder;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates an example-workflowtrace for Man-in-the-Middle Attack
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class RSAExampleMitMWorkflowConfiguration {

    private final TlsContext tlsContext;
    private final CommandConfig config;

    public RSAExampleMitMWorkflowConfiguration(TlsContext tlsContext, CommandConfig config) {
	this.tlsContext = tlsContext;
	this.config = config;
    }

    public void createWorkflow() {

	ClientCommandConfig ccConfig = (ClientCommandConfig) config;
	WorkflowTraceType workflowTraceType = ccConfig.getWorkflowTraceType();

	WorkflowTrace workflowTrace;

	switch (workflowTraceType) {
	    case FULL_SERVER_RESPONSE:
		workflowTrace = createFullSRWorkflow();
		break;
	    case FULL:
		workflowTrace = createFullWorkflow();
		break;
	    case HANDSHAKE:
		workflowTrace = createHandshakeWorkflow();
		break;
	    default:
		throw new ConfigurationException("not supported workflow type: " + workflowTraceType);
	}

	tlsContext.setWorkflowTrace(workflowTrace);

	initializeProtocolMessageOrder(tlsContext);
    }

    private WorkflowTrace createHandshakeWorkflow() {

	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new LinkedList<>();

	ClientHelloMessage ch = new ClientHelloMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(ch);

	ServerHelloMessage sh = new ServerHelloMessage(ConnectionEnd.SERVER);
	protocolMessages.add(sh);
	CertificateMessage cm = new CertificateMessage(ConnectionEnd.SERVER);
	protocolMessages.add(cm);
	cm.setGoingToBeSent(false);

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateRequestMessage(ConnectionEnd.SERVER));
	}

	protocolMessages.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	if (tlsContext.isClientAuthentication()) {
	    protocolMessages.add(new CertificateMessage(ConnectionEnd.CLIENT));
	}

	RSAClientKeyExchangeMessage kem = new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(kem);
	kem.setGoingToBeSent(false);

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

	ApplicationMessage cam = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(cam);
	cam.setGoingToBeSent(false);

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;
    }

    private WorkflowTrace createFullSRWorkflow() {

	WorkflowTrace workflowTrace = this.createFullWorkflow();

	List<ProtocolMessage> protocolMessages = workflowTrace.getProtocolMessages();

	ApplicationMessage sam = new ApplicationMessage(ConnectionEnd.SERVER);
	protocolMessages.add(sam);
	sam.setModify(true);

	workflowTrace.setProtocolMessages(protocolMessages);

	return workflowTrace;
    }

}
