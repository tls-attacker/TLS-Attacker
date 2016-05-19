/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;

/**
 * Creates configuration of implemented ECDH(E) functionality in the protocol.
 * 
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DtlsEcdhWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    private final CommandConfig config;

    DtlsEcdhWorkflowConfigurationFactory(CommandConfig config) {
	this.config = config;
    }

    @Override
    public TlsContext createClientHelloTlsContext() {
	TlsContext context = new TlsContext();
	context.setProtocolVersion(config.getProtocolVersion());

	context.setSelectedCipherSuite(config.getCipherSuites().get(0));
	WorkflowTrace workflowTrace = new WorkflowTrace();

	ClientHelloDtlsMessage ch = new ClientHelloDtlsMessage(ConnectionEnd.CLIENT);
	workflowTrace.add(ch);

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());
	ch.setIncludeInDigest(false);

	initializeClientHelloExtensions(config, ch);

	HelloVerifyRequestMessage hvrm = new HelloVerifyRequestMessage(ConnectionEnd.SERVER);
	hvrm.setIncludeInDigest(false);
	workflowTrace.add(hvrm);

	ch = new ClientHelloDtlsMessage(ConnectionEnd.CLIENT);
	workflowTrace.add(ch);

	ch.setSupportedCipherSuites(config.getCipherSuites());
	ch.setSupportedCompressionMethods(config.getCompressionMethods());

	initializeClientHelloExtensions(config, ch);

	context.setWorkflowTrace(workflowTrace);
	initializeProtocolMessageOrder(context);

	return context;
    }

    @Override
    public TlsContext createHandshakeTlsContext() {
	TlsContext context = this.createClientHelloTlsContext();

	WorkflowTrace workflowTrace = context.getWorkflowTrace();
	workflowTrace.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	workflowTrace.add(new CertificateMessage(ConnectionEnd.SERVER));

	if (config.getCipherSuites().get(0).isEphemeral()) {
	    workflowTrace.add(new ECDHEServerKeyExchangeMessage(ConnectionEnd.SERVER));
	}

	if (config.getKeystore() != null && config.isClientAuthentication()) {
	    workflowTrace.add(new CertificateRequestMessage(ConnectionEnd.SERVER));
	    workflowTrace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	    workflowTrace.add(new CertificateMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new ECDHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new CertificateVerifyMessage(ConnectionEnd.CLIENT));
	} else {
	    workflowTrace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));
	    workflowTrace.add(new ECDHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	}

	workflowTrace.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	workflowTrace.add(new FinishedMessage(ConnectionEnd.CLIENT));

	workflowTrace.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	workflowTrace.add(new FinishedMessage(ConnectionEnd.SERVER));

	initializeProtocolMessageOrder(context);

	return context;
    }

    @Override
    public TlsContext createFullTlsContext() {
	TlsContext context = this.createHandshakeTlsContext();

	WorkflowTrace workflowTrace = context.getWorkflowTrace();
	workflowTrace.add(new ApplicationMessage(ConnectionEnd.CLIENT));

	if (config.getHeartbeatMode() != null) {
	    workflowTrace.add(new HeartbeatMessage(ConnectionEnd.CLIENT));
	    workflowTrace.add(new HeartbeatMessage(ConnectionEnd.SERVER));
	}

	AlertMessage alertMessage = new AlertMessage(ConnectionEnd.CLIENT);
	alertMessage.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
	workflowTrace.add(alertMessage);

	initializeProtocolMessageOrder(context);

	return context;
    }

}
