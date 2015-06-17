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

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.ServerCommandConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class Main {

    public static void main(String[] args) throws Exception {

	// ECC does not work properly in the NSS provider
	Security.removeProvider("SunPKCS11-NSS");
	Security.addProvider(new BouncyCastleProvider());

	GeneralConfig generalConfig = new GeneralConfig();
	JCommander jc = new JCommander(generalConfig);

	ServerCommandConfig server = new ServerCommandConfig();
	jc.addCommand(ServerCommandConfig.COMMAND, server);
	ClientCommandConfig client = new ClientCommandConfig();
	jc.addCommand(ClientCommandConfig.COMMAND, client);

	jc.parse(args);

	if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
	    jc.usage();
	    return;
	}

	CommandConfig config;
	if (jc.getParsedCommand().equals(ServerCommandConfig.COMMAND)) {
	    config = server;
	} else {
	    config = client;
	}

	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler(jc.getParsedCommand());
	configHandler.initializeGeneralConfig(generalConfig);

	if (configHandler.printHelpForCommand(jc, config)) {
	    return;
	}

	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	workflowExecutor.executeWorkflow();

	// if (config.isVerifyWorkflowCorrectness()) {
	// workflowExecutor.checkConfiguredProtocolMessagesOrder();
	// }

	transportHandler.closeConnection();
    }
}
