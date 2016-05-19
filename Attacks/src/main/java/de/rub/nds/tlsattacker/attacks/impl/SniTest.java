/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.SniTestCommandConfig;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.NameType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends different server names in the SNI extension in the ClientHello
 * messages.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class SniTest extends Attacker<SniTestCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(SniTest.class);

    public SniTest(SniTestCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	List<ProtocolMessage> messages = trace.getProtocolMessages();
	ServerNameIndicationExtensionMessage sni = new ServerNameIndicationExtensionMessage();
	sni.setServerNameConfig(config.getServerName2());
	sni.setNameTypeConfig(NameType.HOST_NAME);
	ClientHelloMessage ch2 = (ClientHelloMessage) UnoptimizedDeepCopy.copy(messages.get(0));
	ch2.addExtension(sni);
	messages.add(ch2);
	messages.add(new ServerHelloMessage());
	messages.add(new CertificateMessage());

	workflowExecutor.executeWorkflow();
	transportHandler.closeConnection();

    }

}
