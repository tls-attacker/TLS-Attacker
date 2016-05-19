/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.config.ServerCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import static de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory.initializeClientHelloExtensions;
import static de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory.initializeProtocolMessageOrder;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates Workflowtrace for Session Resumption
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class SessionResumptionWorkflowConfiguration {

    private final TlsContext tlsContext;
    private final CommandConfig config;

    public SessionResumptionWorkflowConfiguration(TlsContext tlsContext, CommandConfig config) {
	this.tlsContext = tlsContext;
	this.config = config;
    }

    public void createWorkflow() {
	tlsContext.setSessionResumption(true);
	tlsContext.getDigest().reset();
	WorkflowTraceType workflowTraceType;
	if (tlsContext.getMyConnectionEnd() == ConnectionEnd.CLIENT) {
	    ClientCommandConfig ccConfig = (ClientCommandConfig) config;
	    workflowTraceType = ccConfig.getWorkflowTraceType();
	} else {
	    ServerCommandConfig ccConfig = (ServerCommandConfig) config;
	    workflowTraceType = ccConfig.getWorkflowTraceType();
	}

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

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());

	initializeClientHelloExtensions(config, ch);

	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.SERVER));

	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.CLIENT));

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
