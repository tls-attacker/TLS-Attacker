/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.fuzzer;

import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlsattacker.util.ServerStartCommandExecutor;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class FuzzerTest {

    private static final String COMMAND = "/home/juraj/NetBeansProjects/openssl-1.0.1f/apps/openssl s_server -accept 51624 -key /home/juraj/svn/repos_misc/builder-tasks/TLS-Attacker/resources/privkey1024.pem -cert /home/juraj/svn/repos_misc/builder-tasks/TLS-Attacker/resources/server-cert1024.pem";

    // private static final String COMMAND =
    // "/home/juraj/NetBeansProjects/polarssl-1.3.9/programs/ssl/ssl_server";
    // /usr/lib/jvmdk1.8.0_05/bin/java -jar
    // SSLServer-1.0-SNAPSHOT-jar-with-dependencies.jar eckey192.jks password
    // TLS 51624
    public static void main(String[] args) throws Exception {

	ServerStartCommandExecutor sce = new ServerStartCommandExecutor(COMMAND);
	sce.startServer();

	Security.addProvider(new BouncyCastleProvider());
	// TransportHandler th =
	// TransportHandlerFactory.createTransportHandler(TransportHandlerType.SIMPLE);
	// th.initialize("localhost", 51624);
	// controller.setTransportHandler(th);

	// WorkflowConfigurationFactory factory =
	// WorkflowConfigurationFactory.createInstance(WorkflowConfigurationFactory.TYPE.RSA,
	// ProtocolVersion.TLS12);
	// WorkflowTrace workflow = factory.createHandshakeTlsContext();
	// controller.setWorkflowTrace(workflow);
	//
	// WorkflowExecutor executor =
	// WorkflowExecutorFactory.createWorkflowExecutor();
	// controller.setWorkflowExecutor(executor);
	//
	// ModifiableVariableHolder holder =
	// FuzzingHelper.getRandomModifiableVariableHolder(workflow,
	// ConnectionEnd.CLIENT);
	// FuzzingHelper.executeRandomModifiableVariableModification(holder);
	//
	// FuzzingHelper.addRecordsAtRandom(workflow, ConnectionEnd.CLIENT);
	//
	// executor.executeWorkflow();
	//
	// System.out.println(sce.getServerOutputString());
	// System.out.println(sce.getServerErrorOutputString());
    }
}
