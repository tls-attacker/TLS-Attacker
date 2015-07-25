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
package de.rub.nds.tlsattacker.dtls.workflow;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ClientConfigHandler;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.UDPTransportHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class Dtls12WorkflowExecutorTest {

    public Dtls12WorkflowExecutorTest() {
	Security.removeProvider("SunPKCS11-NSS");
	Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testExecuteWorkflow() {
	// try {
	// DatagramSocket ds = new DatagramSocket(45481,
	// InetAddress.getByName("127.0.0.1"));
	//
	// } catch (UnknownHostException | SocketException ex) {
	// fail(ex.getMessage());
	// }
	// ClientCommandConfig config = new ClientCommandConfig();
	// ClientConfigHandler configHandler = new ClientConfigHandler();
	//
	// config.setProtocolVersion(ProtocolVersion.DTLS12);
	// config.setConnect("127.0.0.1:4444");
	// config.setTransportHandlerType(TransportHandlerType.UDP);
	// // ArrayList<CipherSuite> test = new ArrayList<>();
	// // test.add(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA);
	// // config.setCipherSuites(test);
	//
	// TransportHandler th =
	// configHandler.initializeTransportHandler(config);
	//
	// TlsContext context =
	// WorkflowConfigurationFactory.createInstance(config).createHandshakeTlsContext();
	// context.setMyConnectionEnd(ConnectionEnd.CLIENT);
	// Dtls12WorkflowExecutor workflowExecutor = new
	// Dtls12WorkflowExecutor(th, context);
	// workflowExecutor.executeWorkflow();
    }
}
