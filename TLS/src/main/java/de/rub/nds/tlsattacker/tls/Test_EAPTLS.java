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

/**
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class Test_EAPTLS {

    // /usr/lib/jvmdk1.8.0_05/bin/java -jar
    // SSLServer-1.0-SNAPSHOT-jar-with-dependencies.jar eckey192.jks password
    // TLS 51624
    public static void main(String[] args) throws Exception {

	// // ECC does not work properly in the NSS provider
	// Security.removeProvider("SunPKCS11-NSS");
	// Security.addProvider(new BouncyCastleProvider());
	//
	// ProtocolController controller = ProtocolController.getInstance();
	// TransportHandler th =
	// TransportHandlerFactory.createTransportHandler(TransportHandlerType.EAP_TLS);
	// th.initialize("EAP", 23);
	// controller.setTransportHandler(th);
	//
	// WorkflowConfigurationFactory factory =
	// WorkflowConfigurationFactory.createInstance(WorkflowConfigurationFactory.TYPE.RSA,
	// ProtocolVersion.TLS12);
	// WorkflowTrace workflow = factory.createBasicWorkflowTrace();
	// controller.setWorkflowTrace(workflow);
	//
	// WorkflowExecutor executor =
	// WorkflowExecutorFactory.createWorkflowExecutor();
	// controller.setWorkflowExecutor(executor);
	//
	// executor.executeWorkflow();
    }
}
