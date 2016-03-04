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

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageTypeHolder;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates Workflowtrace for Session Resumption
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class SessionResumptionWorkflowConfiguration {

    public final TlsContext tlsContext;

    public SessionResumptionWorkflowConfiguration(TlsContext tlsContext) {
	this.tlsContext = tlsContext;
    }

    public void createHandshakeWorkflow() {

	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new LinkedList<>();

	protocolMessages.add(new ClientHelloMessage(ConnectionEnd.CLIENT));

	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.SERVER));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.CLIENT));

	workflowTrace.setProtocolMessages(protocolMessages);

	tlsContext.setWorkflowTrace(workflowTrace);

	initializeProtocolMessageOrder(tlsContext);

	tlsContext.setSessionResumption(true);

    }

    public void createFullWorkflow() {

	WorkflowTrace workflowTrace = new WorkflowTrace();

	List<ProtocolMessage> protocolMessages = new LinkedList<>();

	protocolMessages.add(new ClientHelloMessage(ConnectionEnd.CLIENT));

	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.SERVER));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.CLIENT));

	protocolMessages.add(new ApplicationMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new ApplicationMessage(ConnectionEnd.SERVER));

	workflowTrace.setProtocolMessages(protocolMessages);

	tlsContext.setWorkflowTrace(workflowTrace);

	initializeProtocolMessageOrder(tlsContext);

	tlsContext.setSessionResumption(true);

    }

    /**
     * Initializes the preconfigured protocol message order according to the
     * workflow trace. This protocol message order can be used to compare the
     * configured and real message order.
     * 
     * @param context
     */
    public static void initializeProtocolMessageOrder(TlsContext context) {
	List<ProtocolMessageTypeHolder> configuredProtocolMessageOrder = new LinkedList<>();
	for (ProtocolMessage pm : context.getWorkflowTrace().getProtocolMessages()) {
	    ProtocolMessageTypeHolder pmth = new ProtocolMessageTypeHolder(pm);
	    configuredProtocolMessageOrder.add(pmth);
	}
	context.setPreconfiguredProtocolMessages(configuredProtocolMessageOrder);
    }

}
