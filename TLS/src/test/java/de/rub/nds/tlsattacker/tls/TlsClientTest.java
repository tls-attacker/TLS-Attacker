/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.PublicKeyAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.tlsserver.KeyStoreGenerator;
import de.rub.nds.tlsattacker.tlsserver.TLSServer;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import java.util.Set;
import static org.hamcrest.Matchers.is;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.ErrorCollector;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TlsClientTest {
    @Rule
    public ErrorCollector collector = new ErrorCollector();
    private static final Logger LOGGER = LogManager.getLogger(TlsClientTest.class);

    private TLSServer tlsServer;

    private static final int PORT = 56789;

    private static final int TIMEOUT = 400;

    public TlsClientTest() {
	Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testRSAWorkflows() {
	try {
            
	    KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
	    KeyStore ks = KeyStoreGenerator.createKeyStore(k);
	    tlsServer = new TLSServer(ks, KeyStoreGenerator.PASSWORD, "TLS", PORT);
	    new Thread(tlsServer).start();
	    while (!tlsServer.isInitialized())
		;
	    LOGGER.log(Level.INFO, "Testing RSA");
	    testExecuteWorkflows(PublicKeyAlgorithm.RSA, PORT);
	    tlsServer.shutdown();
	} catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
		| KeyStoreException | NoSuchProviderException | SignatureException | OperatorCreationException
		| UnrecoverableKeyException | KeyManagementException e) {
	    LOGGER.error("Unable to initialize the TLS server with an RSA key, but the build runs further.", e);
	}
    }

    @Test
    public void testECWorkflows() {
	try {
	    KeyPair k = KeyStoreGenerator.createECKeyPair(256);
	    KeyStore ks = KeyStoreGenerator.createKeyStore(k);
	    tlsServer = new TLSServer(ks, KeyStoreGenerator.PASSWORD, "TLS", PORT + 1);
	    new Thread(tlsServer).start();
	    while (!tlsServer.isInitialized())
		;
	    LOGGER.log(Level.INFO, "Testing EC");
	    testExecuteWorkflows(PublicKeyAlgorithm.EC, PORT + 1);
	    tlsServer.shutdown();
	} catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
		| KeyStoreException | NoSuchProviderException | SignatureException | OperatorCreationException
		| UnrecoverableKeyException | KeyManagementException e) {
	    LOGGER.error("Unable to initialize the TLS server with an EC key, but the build runs further.", e);
	}
    }

    /**
     * Test of executeWorkflow method, of class WorkflowExecutor.
     * 
     * @param algorithm
     * @param port
     */
    public void testExecuteWorkflows(PublicKeyAlgorithm algorithm, int port) {
	GeneralConfig generalConfig = new GeneralConfig();
	generalConfig.setLogLevel(Level.INFO);
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);
	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect("localhost:" + port);
	config.setTlsTimeout(TIMEOUT);
	configHandler.initializeTransportHandler(config);

	List<String> serverList = Arrays.asList(tlsServer.getCipherSuites());
	config.setProtocolVersion(ProtocolVersion.TLS10);
	testProtocolCompatibility(serverList, configHandler, config, algorithm);
	config.setProtocolVersion(ProtocolVersion.TLS11);
	testProtocolCompatibility(serverList, configHandler, config, algorithm);
	config.setProtocolVersion(ProtocolVersion.TLS12);
	testProtocolCompatibility(serverList, configHandler, config, algorithm);

	if (algorithm == PublicKeyAlgorithm.RSA) {
	    testCustomWorkflow(port);
	}

    }

    private void testProtocolCompatibility(List<String> serverList, ConfigHandler configHandler,
	    ClientCommandConfig config, PublicKeyAlgorithm algorithm) {
	LOGGER.info(config.getProtocolVersion());
	for (CipherSuite cs : CipherSuite.getImplemented()) {
	    Set<PublicKeyAlgorithm> requiredAlgorithms = AlgorithmResolver.getRequiredKeystoreAlgorithms(cs);
	    requiredAlgorithms.remove(algorithm);
	    if (serverList.contains(cs.toString()) && cs.isSupportedInProtocol(config.getProtocolVersion())
		    && requiredAlgorithms.isEmpty()) {
		LinkedList<CipherSuite> cslist = new LinkedList<>();
		cslist.add(cs);
		config.setCipherSuites(cslist);
		boolean result = testExecuteWorkflow(configHandler, config);
		LOGGER.info("Testing: " + cs.name() + " Succes:" + result);
		collector.checkThat("" + cs.name() + " failed.", result, is(true));
	    }
	}
    }

    private boolean testExecuteWorkflow(ConfigHandler configHandler, ClientCommandConfig config) {

	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);

	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	try {
	    workflowExecutor.executeWorkflow();
	} catch (Exception E) {
	    E.printStackTrace();
	}
	transportHandler.closeConnection();
	boolean result = isWorkflowTraceReasonable(tlsContext.getWorkflowTrace());
	if (!result) {
	    LOGGER.log(Level.INFO, "Failed vanilla execution");
	    return result;
	}
	tlsContext.getWorkflowTrace().reset();
	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	tlsContext = configHandler.initializeTlsContext(config);
	tlsContext.setWorkflowTrace(trace);
	transportHandler = configHandler.initializeTransportHandler(config);
	workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	try {
	    workflowExecutor.executeWorkflow();
	} catch (Exception E) {
	    E.printStackTrace();
	}
	transportHandler.closeConnection();
	result = isWorkflowTraceReasonable(tlsContext.getWorkflowTrace());
	if (!result) {
	    LOGGER.log(Level.INFO, "Failed reset execution");
	    return result;
	}
	tlsContext.getWorkflowTrace().reset();
	tlsContext.getWorkflowTrace().makeGeneric();
	trace = tlsContext.getWorkflowTrace();
	tlsContext = configHandler.initializeTlsContext(config);
	tlsContext.setWorkflowTrace(trace);
	transportHandler = configHandler.initializeTransportHandler(config);
	workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	try {
	    workflowExecutor.executeWorkflow();
	} catch (Exception E) {
	    E.printStackTrace();
	}
	transportHandler.closeConnection();
	result = isWorkflowTraceReasonable(tlsContext.getWorkflowTrace());
	if (!result) {
	    LOGGER.log(Level.INFO, "Failed reset&generic execution");
	}
	return result;
    }
    private boolean isWorkflowTraceReasonable(WorkflowTrace trace) {
	int counter = 0;
	for (ProtocolMessage configuredMessage : trace.getAllConfiguredMessages()) {
	    if (counter >= trace.getAllExecutedMessages().size()) {
		return false;
	    }
	    ProtocolMessage receivedMessage = trace.getAllExecutedMessages().get(counter);
	    if (configuredMessage.getClass().equals(ArbitraryMessage.class)) {
		break;
	    }
	    if (configuredMessage.getClass() != receivedMessage.getClass()) {
		if (configuredMessage.isRequired()) {
		    return false;
		}
	    } else {
		counter++;
	    }
	}
	return (!trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED).isEmpty());
    }

    private void testCustomWorkflow(int port) {
	GeneralConfig generalConfig = new GeneralConfig();
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);

	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect("localhost:" + port);
	config.setTlsTimeout(TIMEOUT);
	config.setWorkflowTraceType(WorkflowTraceType.CLIENT_HELLO);

	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	trace.add(MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.SERVER,
		new ServerHelloMessage(), new CertificateMessage(), new ServerHelloDoneMessage()));

	trace.add(MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.CLIENT,
		new RSAClientKeyExchangeMessage(), new ChangeCipherSpecMessage(), new FinishedMessage()));
	trace.add(MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.SERVER,
		new ChangeCipherSpecMessage(), new FinishedMessage()));
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();
	assertTrue(!tlsContext.getWorkflowTrace()
		.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED).isEmpty());
    }

}
