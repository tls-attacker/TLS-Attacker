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
package de.rub.nds.tlsattacker.tls;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tlsserver.KeyStoreGenerator;
import de.rub.nds.tlsattacker.tlsserver.TLSServer;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

    private final int PORT = 56789;

    public TlsClientTest() {
	Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setUp() throws Exception {
	KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
	KeyStore ks = KeyStoreGenerator.createKeyStore(k);
	tlsServer = new TLSServer(ks, KeyStoreGenerator.PASSWORD, "TLS", PORT);
	new Thread(tlsServer).start();
    }

    @After
    public void tearDown() throws Exception {
	tlsServer.shutdown();
    }

    /**
     * Test of executeWorkflow method, of class WorkflowExecutor.
     */
    @Test
    public void testExecuteWorkflows() {

	GeneralConfig generalConfig = new GeneralConfig();
	generalConfig.setLogLevel(Level.INFO);
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initializeGeneralConfig(generalConfig);

	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect("localhost:" + PORT);

	List<String> serverList = Arrays.asList(tlsServer.getCipherSuites());
	for (CipherSuite cs : CipherSuite.getImplemented()) {
	    if (serverList.contains(cs.toString())) {
		LOGGER.info("Testing: {}", cs);
		testExecuteWorkflow(configHandler, config);
	    }
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

}
