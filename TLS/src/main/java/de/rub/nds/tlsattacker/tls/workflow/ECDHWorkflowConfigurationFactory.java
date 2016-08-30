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
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import static de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory.initializeProtocolMessageOrder;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates configuration of implemented ECDH(E) functionality in the protocol.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    ECDHWorkflowConfigurationFactory(CommandConfig config) {
	super(config);
    }

    @Override
    public TlsContext createHandshakeTlsContext(ConnectionEnd myConnectionEnd) {
	TlsContext context = this.createClientHelloTlsContext(myConnectionEnd);
	List<ProtocolMessage> messages = new LinkedList<>();
	WorkflowTrace workflowTrace = context.getWorkflowTrace();
	messages.add(new ServerHelloMessage());
	messages.add(new CertificateMessage());

	if (config.getCipherSuites().get(0).isEphemeral()) {
	    messages.add(new ECDHEServerKeyExchangeMessage());
	}

	if (config.getKeystore() != null && config.isClientAuthentication()) {
	    messages.add(new CertificateRequestMessage());
	    messages.add(new ServerHelloDoneMessage());
	    workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
	    messages = new LinkedList<>();
	    messages.add(new CertificateMessage());
	    messages.add(new ECDHClientKeyExchangeMessage());
	    messages.add(new CertificateVerifyMessage());
	} else {
	    messages.add(new ServerHelloDoneMessage());
	    workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
	    messages = new LinkedList<>();
	    messages.add(new ECDHClientKeyExchangeMessage());
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
