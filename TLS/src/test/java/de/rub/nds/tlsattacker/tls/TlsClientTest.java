/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
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
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TlsClientTest {

    private static final Logger LOGGER = LogManager.getLogger(TlsClientTest.class);

    private TLSServer tlsServer;

    private static final int PORT = 56789;

    private boolean initialized;

    public TlsClientTest() {
	Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setUp() {
	try {
	    KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
	    KeyStore ks = KeyStoreGenerator.createKeyStore(k);
	    tlsServer = new TLSServer(ks, KeyStoreGenerator.PASSWORD, "TLS", PORT);
	    new Thread(tlsServer).start();
	    initialized = true;
	} catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
		| KeyStoreException | NoSuchProviderException | SignatureException | OperatorCreationException
		| UnrecoverableKeyException | KeyManagementException e) {
	    LOGGER.error("Unable to initialize the TLS server, but the build runs further.", e);
	}
    }

    @After
    public void tearDown() throws Exception {
	if (initialized) {
	    tlsServer.shutdown();
	}
    }

    /**
     * Test of executeWorkflow method, of class WorkflowExecutor.
     */
    @Test
    public void testExecuteWorkflows() {
	if (initialized) {
	    GeneralConfig generalConfig = new GeneralConfig();
	    generalConfig.setLogLevel(Level.INFO);
	    ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	    configHandler.initialize(generalConfig);

	    ClientCommandConfig config = new ClientCommandConfig();
	    config.setConnect("localhost:" + PORT);

	    List<String> serverList = Arrays.asList(tlsServer.getCipherSuites());
	    for (CipherSuite cs : CipherSuite.getImplemented()) {
		if (serverList.contains(cs.toString())) {
		    LOGGER.info("Testing: {}", cs);
		    testExecuteWorkflow(configHandler, config);
		}
	    }

	    testCustomWorkflow();
	}
    }

    private void testExecuteWorkflow(ConfigHandler configHandler, ClientCommandConfig config) {

	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();

	assertTrue(tlsContext.getWorkflowTrace().containsServerFinished());
    }

    private void testCustomWorkflow() {
	GeneralConfig generalConfig = new GeneralConfig();
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);

	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect("localhost:" + PORT);
	config.setWorkflowTraceType(WorkflowTraceType.CLIENT_HELLO);

	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	trace.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	trace.add(new CertificateMessage(ConnectionEnd.SERVER));
	trace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));
	trace.add(new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	trace.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	trace.add(new FinishedMessage(ConnectionEnd.CLIENT));
	trace.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	trace.add(new FinishedMessage(ConnectionEnd.SERVER));

	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();

	assertTrue(tlsContext.getWorkflowTrace().containsServerFinished());
    }

}
