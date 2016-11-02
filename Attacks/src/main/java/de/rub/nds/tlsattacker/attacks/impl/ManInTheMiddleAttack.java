/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.ManInTheMiddleAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.mitm.RSAExampleMitMWorkflowConfiguration;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.ServerCommandConfig;
import de.rub.nds.tlsattacker.tls.workflow.GenericWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a generic Man in the Middle attack against a target server and a
 * client.
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ManInTheMiddleAttack extends Attacker<ManInTheMiddleAttackCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(ManInTheMiddleAttack.class);

    public ManInTheMiddleAttack(ManInTheMiddleAttackCommandConfig config) {
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

	GeneralConfig generalConfig = new GeneralConfig();
	ConfigHandler serverConfigHandler = ConfigHandlerFactory.createConfigHandler("server");
	serverConfigHandler.initialize(generalConfig);
	TransportHandler serverTransportHandler = serverConfigHandler.initializeTransportHandler(serverCommandConfig);
	TlsContext serverTlsContext = serverConfigHandler.initializeTlsContext(serverCommandConfig);

	// create client objects
	TransportHandler clientTransportHandler = clientConfigHandler.initializeTransportHandler(config);
	TlsContext clientTlsContext = clientConfigHandler.initializeTlsContext(config);

	// load workflow into the tlsContext objects
	RSAExampleMitMWorkflowConfiguration clientwf = new RSAExampleMitMWorkflowConfiguration(clientTlsContext, config);
	clientwf.createWorkflow();

	RSAExampleMitMWorkflowConfiguration serverwf = new RSAExampleMitMWorkflowConfiguration(serverTlsContext, config);
	serverwf.createWorkflow();

	// should the whole workflow trace be modified
	boolean mod = config.isModify();

        //This should be executable by a normal executor with Forward or MitM actions which are
        //currently not implemented
	GenericWorkflowExecutor executor = new GenericWorkflowExecutor(clientTransportHandler, clientTlsContext, ExecutorType.TLS);
        executor.executeWorkflow();
	clientTransportHandler.closeConnection();
	serverTransportHandler.closeConnection();
    }
}
