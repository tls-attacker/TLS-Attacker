/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates configuration of implemented DH(E) functionality in the protocol.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DHWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    public DHWorkflowConfigurationFactory(CommandConfig config) {
	super(config);
    }

    /**
     * Creates a basic TLS context with a TLS handshake messages
     * 
     * @return
     */
    public TlsContext createHandshakeTlsContext(ConnectionEnd myConnectionEnd) {
	TlsContext context = this.createClientHelloTlsContext(myConnectionEnd);
	List<ProtocolMessage> messages = new LinkedList<>();
	WorkflowTrace workflowTrace = context.getWorkflowTrace();

	messages.add(new ServerHelloMessage());
	messages.add(new CertificateMessage());
	CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage();
	certificateRequestMessage.setRequired(false);

	if (config.getCipherSuites().get(0).isEphemeral()) {
	    messages.add(new DHEServerKeyExchangeMessage());
	    messages.add(certificateRequestMessage);
	}
	if (config.getKeystore() != null && config.isClientAuthentication()) {
	    messages.add(new ServerHelloDoneMessage());
	    workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
	    messages = new LinkedList<>();
	    messages.add(new CertificateMessage());
	    messages.add(new DHClientKeyExchangeMessage());
	    messages.add(new CertificateVerifyMessage());

	} else {
	    messages.add(new ServerHelloDoneMessage());
	    workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
	    messages = new LinkedList<>();
	    messages.add(new DHClientKeyExchangeMessage());
	}
	messages.add(new ChangeCipherSpecMessage());
	messages.add(new FinishedMessage());
	workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.CLIENT, messages));
	messages = new LinkedList<>();
	messages.add(new ChangeCipherSpecMessage());
	messages.add(new FinishedMessage());
	workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
	initializeProtocolMessageOrder(context);

	return context;
    }
}
